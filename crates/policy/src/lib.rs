// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

pub mod model;

use opa_wasm::{
    wasmtime::{Config, Engine, Module, OptLevel, Store},
    Runtime,
};
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

pub use self::model::{
    AuthorizationGrantInput, ClientRegistrationInput, Code as ViolationCode, EmailInput,
    EvaluationResult, GrantType, RegisterInput, RegistrationMethod, Requester, Violation,
};

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read module")]
    Read(#[from] tokio::io::Error),

    #[error("failed to create WASM engine")]
    Engine(#[source] anyhow::Error),

    #[error("module compilation task crashed")]
    CompilationTask(#[from] tokio::task::JoinError),

    #[error("failed to compile WASM module")]
    Compilation(#[source] anyhow::Error),

    #[error("failed to instantiate a test instance")]
    Instantiate(#[source] InstantiateError),
}

#[derive(Debug, Error)]
pub enum InstantiateError {
    #[error("failed to create WASM runtime")]
    Runtime(#[source] anyhow::Error),

    #[error("missing entrypoint {entrypoint}")]
    MissingEntrypoint { entrypoint: String },

    #[error("failed to load policy data")]
    LoadData(#[source] anyhow::Error),
}

/// Holds the entrypoint of each policy
#[derive(Debug, Clone)]
pub struct Entrypoints {
    pub register: String,
    pub client_registration: String,
    pub authorization_grant: String,
    pub email: String,
}

impl Entrypoints {
    fn all(&self) -> [&str; 4] {
        [
            self.register.as_str(),
            self.client_registration.as_str(),
            self.authorization_grant.as_str(),
            self.email.as_str(),
        ]
    }
}

#[derive(Serialize, Debug)]
pub struct Data {
    server_name: String,

    #[serde(flatten)]
    rest: Option<serde_json::Value>,
}

impl Data {
    #[must_use]
    pub fn new(server_name: String) -> Self {
        Self {
            server_name,
            rest: None,
        }
    }

    #[must_use]
    pub fn with_rest(mut self, rest: serde_json::Value) -> Self {
        self.rest = Some(rest);
        self
    }
}

pub struct PolicyFactory {
    engine: Engine,
    module: Module,
    data: Data,
    entrypoints: Entrypoints,
}

impl PolicyFactory {
    #[tracing::instrument(name = "policy.load", skip(source), err)]
    pub async fn load(
        mut source: impl AsyncRead + std::marker::Unpin,
        data: Data,
        entrypoints: Entrypoints,
    ) -> Result<Self, LoadError> {
        let mut config = Config::default();
        config.async_support(true);
        config.cranelift_opt_level(OptLevel::SpeedAndSize);

        let engine = Engine::new(&config).map_err(LoadError::Engine)?;

        // Read and compile the module
        let mut buf = Vec::new();
        source.read_to_end(&mut buf).await?;
        // Compilation is CPU-bound, so spawn that in a blocking task
        let (engine, module) = tokio::task::spawn_blocking(move || {
            let module = Module::new(&engine, buf)?;
            anyhow::Ok((engine, module))
        })
        .await?
        .map_err(LoadError::Compilation)?;

        let factory = Self {
            engine,
            module,
            data,
            entrypoints,
        };

        // Try to instantiate
        factory
            .instantiate()
            .await
            .map_err(LoadError::Instantiate)?;

        Ok(factory)
    }

    #[tracing::instrument(name = "policy.instantiate", skip_all, err)]
    pub async fn instantiate(&self) -> Result<Policy, InstantiateError> {
        let mut store = Store::new(&self.engine, ());
        let runtime = Runtime::new(&mut store, &self.module)
            .await
            .map_err(InstantiateError::Runtime)?;

        // Check that we have the required entrypoints
        let policy_entrypoints = runtime.entrypoints();

        for e in self.entrypoints.all() {
            if !policy_entrypoints.contains(e) {
                return Err(InstantiateError::MissingEntrypoint {
                    entrypoint: e.to_owned(),
                });
            }
        }

        let instance = runtime
            .with_data(&mut store, &self.data)
            .await
            .map_err(InstantiateError::LoadData)?;

        Ok(Policy {
            store,
            instance,
            entrypoints: self.entrypoints.clone(),
        })
    }
}

pub struct Policy {
    store: Store<()>,
    instance: opa_wasm::Policy<opa_wasm::DefaultContext>,
    entrypoints: Entrypoints,
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] anyhow::Error),
}

impl Policy {
    #[tracing::instrument(
        name = "policy.evaluate_email",
        skip_all,
        fields(
            %input.email,
        ),
        err,
    )]
    pub async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.email, &input)
            .await?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "policy.evaluate.register",
        skip_all,
        fields(
            ?input.registration_method,
            input.username = input.username,
            input.email = input.email,
        ),
        err,
    )]
    pub async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.register, &input)
            .await?;

        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    pub async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.client_registration,
                &input,
            )
            .await?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "policy.evaluate.authorization_grant",
        skip_all,
        fields(
            %input.scope,
            %input.client.id,
        ),
        err,
    )]
    pub async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.authorization_grant,
                &input,
            )
            .await?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_register() {
        let data = Data::new("example.com".to_owned()).with_rest(serde_json::json!({
            "allowed_domains": ["element.io", "*.element.io"],
            "banned_domains": ["staging.element.io"],
        }));

        #[allow(clippy::disallowed_types)]
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("policies")
            .join("policy.wasm");

        let file = tokio::fs::File::open(path).await.unwrap();

        let entrypoints = Entrypoints {
            register: "register/violation".to_owned(),
            client_registration: "client_registration/violation".to_owned(),
            authorization_grant: "authorization_grant/violation".to_owned(),
            email: "email/violation".to_owned(),
        };

        let factory = PolicyFactory::load(file, data, entrypoints).await.unwrap();

        let mut policy = factory.instantiate().await.unwrap();

        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@example.com"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                },
            })
            .await
            .unwrap();
        assert!(!res.valid());

        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@foo.element.io"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                },
            })
            .await
            .unwrap();
        assert!(res.valid());

        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("hello@staging.element.io"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                },
            })
            .await
            .unwrap();
        assert!(!res.valid());
    }
}
