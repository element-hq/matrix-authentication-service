// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

pub mod model;

use std::sync::Arc;

use arc_swap::ArcSwap;
use mas_data_model::Ulid;
use opa_wasm::{
    Runtime,
    wasmtime::{Config, Engine, Module, OptLevel, Store},
};
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

    #[error("invalid policy data")]
    InvalidData(#[source] anyhow::Error),

    #[error("failed to instantiate a test instance")]
    Instantiate(#[source] InstantiateError),
}

impl LoadError {
    /// Creates an example of an invalid data error, used for API response
    /// documentation
    #[doc(hidden)]
    #[must_use]
    pub fn invalid_data_example() -> Self {
        Self::InvalidData(anyhow::Error::msg("Failed to merge policy data objects"))
    }
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

#[derive(Debug)]
pub struct Data {
    server_name: String,

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

    fn to_value(&self) -> Result<serde_json::Value, anyhow::Error> {
        let base = serde_json::json!({
            "server_name": self.server_name,
        });

        if let Some(rest) = &self.rest {
            merge_data(base, rest.clone())
        } else {
            Ok(base)
        }
    }
}

fn value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Object(_) => "object",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Null => "null",
    }
}

fn merge_data(
    mut left: serde_json::Value,
    right: serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    merge_data_rec(&mut left, right)?;
    Ok(left)
}

fn merge_data_rec(
    left: &mut serde_json::Value,
    right: serde_json::Value,
) -> Result<(), anyhow::Error> {
    match (left, right) {
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            for (key, value) in right {
                if let Some(left_value) = left.get_mut(&key) {
                    merge_data_rec(left_value, value)?;
                } else {
                    left.insert(key, value);
                }
            }
        }
        (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
            left.extend(right);
        }
        // Other values override
        (serde_json::Value::Number(left), serde_json::Value::Number(right)) => {
            *left = right;
        }
        (serde_json::Value::Bool(left), serde_json::Value::Bool(right)) => {
            *left = right;
        }
        (serde_json::Value::String(left), serde_json::Value::String(right)) => {
            *left = right;
        }

        // Null gets overridden by anything
        (left, right) if left.is_null() => *left = right,

        // Null on the right makes the left value null
        (left, right) if right.is_null() => *left = right,

        (left, right) => anyhow::bail!(
            "Cannot merge a {} into a {}",
            value_kind(&right),
            value_kind(left),
        ),
    }

    Ok(())
}

struct DynamicData {
    version: Option<Ulid>,
    merged: serde_json::Value,
}

pub struct PolicyFactory {
    engine: Engine,
    module: Module,
    data: Data,
    dynamic_data: ArcSwap<DynamicData>,
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

        let merged = data.to_value().map_err(LoadError::InvalidData)?;
        let dynamic_data = ArcSwap::new(Arc::new(DynamicData {
            version: None,
            merged,
        }));

        let factory = Self {
            engine,
            module,
            data,
            dynamic_data,
            entrypoints,
        };

        // Try to instantiate
        factory
            .instantiate()
            .await
            .map_err(LoadError::Instantiate)?;

        Ok(factory)
    }

    /// Set the dynamic data for the policy.
    ///
    /// The `dynamic_data` object is merged with the static data given when the
    /// policy was loaded.
    ///
    /// Returns `true` if the data was updated, `false` if the version
    /// of the dynamic data was the same as the one we already have.
    ///
    /// # Errors
    ///
    /// Returns an error if the data can't be merged with the static data, or if
    /// the policy can't be instantiated with the new data.
    pub async fn set_dynamic_data(
        &self,
        dynamic_data: mas_data_model::PolicyData,
    ) -> Result<bool, LoadError> {
        // Check if the version of the dynamic data we have is the same as the one we're
        // trying to set
        if self.dynamic_data.load().version == Some(dynamic_data.id) {
            // Don't do anything if the version is the same
            return Ok(false);
        }

        let static_data = self.data.to_value().map_err(LoadError::InvalidData)?;
        let merged = merge_data(static_data, dynamic_data.data).map_err(LoadError::InvalidData)?;

        // Try to instantiate with the new data
        self.instantiate_with_data(&merged)
            .await
            .map_err(LoadError::Instantiate)?;

        // If instantiation succeeds, swap the data
        self.dynamic_data.store(Arc::new(DynamicData {
            version: Some(dynamic_data.id),
            merged,
        }));

        Ok(true)
    }

    #[tracing::instrument(name = "policy.instantiate", skip_all, err)]
    pub async fn instantiate(&self) -> Result<Policy, InstantiateError> {
        let data = self.dynamic_data.load();
        self.instantiate_with_data(&data.merged).await
    }

    async fn instantiate_with_data(
        &self,
        data: &serde_json::Value,
    ) -> Result<Policy, InstantiateError> {
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
            .with_data(&mut store, data)
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

    use std::time::SystemTime;

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

    #[tokio::test]
    async fn test_dynamic_data() {
        let data = Data::new("example.com".to_owned());

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
        assert!(res.valid());

        // Update the policy data
        factory
            .set_dynamic_data(mas_data_model::PolicyData {
                id: Ulid::nil(),
                created_at: SystemTime::now().into(),
                data: serde_json::json!({
                    "emails": {
                        "banned_addresses": {
                            "substrings": ["hello"]
                        }
                    }
                }),
            })
            .await
            .unwrap();
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
    }

    #[tokio::test]
    async fn test_big_dynamic_data() {
        let data = Data::new("example.com".to_owned());

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

        // That is around 1 MB of JSON data. Each element is a 5-digit string, so 8
        // characters including the quotes and a comma.
        let data: Vec<String> = (0..(1024 * 1024 / 8))
            .map(|i| format!("{:05}", i % 100_000))
            .collect();
        let json = serde_json::json!({ "emails": { "banned_addresses": { "substrings": data } } });
        factory
            .set_dynamic_data(mas_data_model::PolicyData {
                id: Ulid::nil(),
                created_at: SystemTime::now().into(),
                data: json,
            })
            .await
            .unwrap();

        // Try instantiating the policy, make sure 5-digit numbers are banned from email
        // addresses
        let mut policy = factory.instantiate().await.unwrap();
        let res = policy
            .evaluate_register(RegisterInput {
                registration_method: RegistrationMethod::Password,
                username: "hello",
                email: Some("12345@example.com"),
                requester: Requester {
                    ip_address: None,
                    user_agent: None,
                },
            })
            .await
            .unwrap();
        assert!(!res.valid());
    }

    #[test]
    fn test_merge() {
        use serde_json::json as j;

        // Merging objects
        let res = merge_data(j!({"hello": "world"}), j!({"foo": "bar"})).unwrap();
        assert_eq!(res, j!({"hello": "world", "foo": "bar"}));

        // Override a value of the same type
        let res = merge_data(j!({"hello": "world"}), j!({"hello": "john"})).unwrap();
        assert_eq!(res, j!({"hello": "john"}));

        let res = merge_data(j!({"hello": true}), j!({"hello": false})).unwrap();
        assert_eq!(res, j!({"hello": false}));

        let res = merge_data(j!({"hello": 0}), j!({"hello": 42})).unwrap();
        assert_eq!(res, j!({"hello": 42}));

        // Override a value of a different type
        merge_data(j!({"hello": "world"}), j!({"hello": 123}))
            .expect_err("Can't merge different types");

        // Merge arrays
        let res = merge_data(j!({"hello": ["world"]}), j!({"hello": ["john"]})).unwrap();
        assert_eq!(res, j!({"hello": ["world", "john"]}));

        // Null overrides a value
        let res = merge_data(j!({"hello": "world"}), j!({"hello": null})).unwrap();
        assert_eq!(res, j!({"hello": null}));

        // Null gets overridden by a value
        let res = merge_data(j!({"hello": null}), j!({"hello": "world"})).unwrap();
        assert_eq!(res, j!({"hello": "world"}));

        // Objects get deeply merged
        let res = merge_data(j!({"a": {"b": {"c": "d"}}}), j!({"a": {"b": {"e": "f"}}})).unwrap();
        assert_eq!(res, j!({"a": {"b": {"c": "d", "e": "f"}}}));
    }
}
