// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::transform::TransformOperation;
use axum::{Json, extract::State};
use mas_data_model::AppVersion;
use schemars::JsonSchema;
use serde::Serialize;

use crate::admin::call_context::CallContext;

#[derive(Serialize, JsonSchema)]
pub struct Version {
    /// The semver version of the app
    pub version: &'static str,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("version")
        .tag("server")
        .summary("Get the version currently running")
        .response_with::<200, Json<Version>, _>(|t| t.example(Version { version: "v1.0.0" }))
}

#[tracing::instrument(name = "handler.admin.v1.version", skip_all)]
pub async fn handler(
    _: CallContext,
    State(AppVersion(version)): State<mas_data_model::AppVersion>,
) -> Json<Version> {
    Json(Version { version })
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_add_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::get("/api/admin/v1/version").bearer(&token).empty();

        let response = state.request(request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "version": "v0.0.0-test"
        }
        "#);
    }
}
