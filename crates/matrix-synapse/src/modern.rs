// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashSet;

use anyhow::Context as _;
use http::{Method, StatusCode};
use mas_http::RequestBuilderExt;
use mas_matrix::{HomeserverConnection, MatrixUser, ProvisionRequest};
use serde::{Deserialize, Serialize};
use tracing::debug;
use url::Url;

use crate::error::{M_EXCLUSIVE, M_INVALID_USERNAME, M_USER_IN_USE, SynapseResponseExt as _};

#[derive(Clone)]
pub struct SynapseConnection {
    homeserver: String,
    endpoint: Url,
    access_token: String,
    http_client: reqwest::Client,
}

impl SynapseConnection {
    #[must_use]
    pub fn new(
        homeserver: String,
        endpoint: Url,
        access_token: String,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            homeserver,
            endpoint,
            access_token,
            http_client,
        }
    }

    fn builder(&self, method: Method, url: &str) -> reqwest::RequestBuilder {
        self.http_client
            .request(
                method,
                self.endpoint
                    .join(url)
                    .map(String::from)
                    .unwrap_or_default(),
            )
            .bearer_auth(&self.access_token)
    }

    fn post(&self, url: &str) -> reqwest::RequestBuilder {
        self.builder(Method::POST, url)
    }

    fn get(&self, url: &str) -> reqwest::RequestBuilder {
        self.builder(Method::GET, url)
    }
}

#[async_trait::async_trait]
impl HomeserverConnection for SynapseConnection {
    fn homeserver(&self) -> &str {
        &self.homeserver
    }

    #[tracing::instrument(
        name = "homeserver.query_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Debug),
    )]
    async fn query_user(&self, localpart: &str) -> Result<MatrixUser, anyhow::Error> {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Response {
            user_id: String,
            display_name: Option<String>,
            avatar_url: Option<String>,
            is_suspended: bool,
            is_deactivated: bool,
        }

        let encoded_localpart = urlencoding::encode(localpart);
        let url = format!("_synapse/mas/query_user?localpart={encoded_localpart}");
        let response = self
            .get(&url)
            .send_traced()
            .await
            .context("Failed to query user from Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while querying user from Synapse")?;

        let body: Response = response
            .json()
            .await
            .context("Failed to deserialize response while querying user from Synapse")?;

        Ok(MatrixUser {
            displayname: body.display_name,
            avatar_url: body.avatar_url,
            deactivated: body.is_deactivated,
        })
    }

    #[tracing::instrument(
        name = "homeserver.provision_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = request.localpart(),
        ),
        err(Debug),
    )]
    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            set_displayname: Option<String>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            unset_displayname: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            set_avatar_url: Option<String>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            unset_avatar_url: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            set_emails: Option<Vec<String>>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            unset_emails: bool,
        }

        let mut body = Request {
            localpart: request.localpart().to_owned(),
            set_displayname: None,
            unset_displayname: false,
            set_avatar_url: None,
            unset_avatar_url: false,
            set_emails: None,
            unset_emails: false,
        };

        request.on_displayname(|displayname| match displayname {
            Some(name) => body.set_displayname = Some(name.to_owned()),
            None => body.unset_displayname = true,
        });

        request.on_avatar_url(|avatar_url| match avatar_url {
            Some(url) => body.set_avatar_url = Some(url.to_owned()),
            None => body.unset_avatar_url = true,
        });

        request.on_emails(|emails| match emails {
            Some(emails) => body.set_emails = Some(emails.to_owned()),
            None => body.unset_emails = true,
        });

        let response = self
            .post("_synapse/mas/provision_user")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to provision user in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while provisioning user in Synapse")?;

        match response.status() {
            StatusCode::CREATED => Ok(true),
            StatusCode::OK => Ok(false),
            code => {
                anyhow::bail!("Unexpected HTTP code while provisioning user in Synapse: {code}")
            }
        }
    }

    #[tracing::instrument(
        name = "homeserver.is_localpart_available",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Debug),
    )]
    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, anyhow::Error> {
        // Synapse will give us an error if the localpart is not ASCII, so we bail out
        // early
        if !localpart.is_ascii() {
            return Ok(false);
        }

        let encoded_localpart = urlencoding::encode(localpart);
        let url = format!("_synapse/mas/is_localpart_available?localpart={encoded_localpart}");
        let response = self
            .get(&url)
            .send_traced()
            .await
            .context("Failed to check localpart availability from Synapse")?;

        match response.error_for_synapse_error().await {
            Ok(_resp) => Ok(true),
            Err(err)
                if err.errcode() == Some(M_INVALID_USERNAME)
                    || err.errcode() == Some(M_USER_IN_USE)
                    || err.errcode() == Some(M_EXCLUSIVE) =>
            {
                debug!(
                    error = &err as &dyn std::error::Error,
                    "Localpart is not available"
                );
                Ok(false)
            }

            Err(err) => Err(err).context("Failed to query localpart availability from Synapse"),
        }
    }

    #[tracing::instrument(
        name = "homeserver.upsert_device",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
            matrix.device_id = device_id,
        ),
        err(Debug),
    )]
    async fn upsert_device(
        &self,
        localpart: &str,
        device_id: &str,
        initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            device_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            display_name: Option<String>,
        }

        let body = Request {
            localpart: localpart.to_owned(),
            device_id: device_id.to_owned(),
            display_name: initial_display_name.map(ToOwned::to_owned),
        };

        let response = self
            .post("_synapse/mas/upsert_device")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to create device in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while creating device in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.update_device_display_name",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
            matrix.device_id = device_id,
        ),
        err(Debug),
    )]
    async fn update_device_display_name(
        &self,
        localpart: &str,
        device_id: &str,
        display_name: &str,
    ) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            device_id: String,
            display_name: String,
        }

        let body = Request {
            localpart: localpart.to_owned(),
            device_id: device_id.to_owned(),
            display_name: display_name.to_owned(),
        };

        let response = self
            .post("_synapse/mas/update_device_display_name")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to update device display name in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while updating device display name in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.delete_device",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
            matrix.device_id = device_id,
        ),
        err(Debug),
    )]
    async fn delete_device(&self, localpart: &str, device_id: &str) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            device_id: String,
        }

        let body = Request {
            localpart: localpart.to_owned(),
            device_id: device_id.to_owned(),
        };

        let response = self
            .post("_synapse/mas/delete_device")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to delete device in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while deleting device in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.sync_devices",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
            matrix.device_count = devices.len(),
        ),
        err(Debug),
    )]
    async fn sync_devices(
        &self,
        localpart: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            devices: Vec<String>,
        }

        let body = Request {
            localpart: localpart.to_owned(),
            devices: devices.into_iter().collect(),
        };

        let response = self
            .post("_synapse/mas/sync_devices")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to sync devices in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while syncing devices in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.delete_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
            matrix.erase = erase,
        ),
        err(Debug),
    )]
    async fn delete_user(&self, localpart: &str, erase: bool) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            erase: bool,
        }

        let body = Request {
            localpart: localpart.to_owned(),
            erase,
        };

        let response = self
            .post("_synapse/mas/delete_user")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to delete user in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while deleting user in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.reactivate_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Debug),
    )]
    async fn reactivate_user(&self, localpart: &str) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
        }

        let body = Request {
            localpart: localpart.to_owned(),
        };

        let response = self
            .post("_synapse/mas/reactivate_user")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to reactivate user in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while reactivating user in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.set_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Debug),
    )]
    async fn set_displayname(
        &self,
        localpart: &str,
        displayname: &str,
    ) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            displayname: String,
        }

        let body = Request {
            localpart: localpart.to_owned(),
            displayname: displayname.to_owned(),
        };

        let response = self
            .post("_synapse/mas/set_displayname")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to set displayname in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while setting displayname in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.unset_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Debug),
    )]
    async fn unset_displayname(&self, localpart: &str) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
        }

        let body = Request {
            localpart: localpart.to_owned(),
        };

        let response = self
            .post("_synapse/mas/unset_displayname")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to unset displayname in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while unsetting displayname in Synapse")?;

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.allow_cross_signing_reset",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Debug),
    )]
    async fn allow_cross_signing_reset(&self, localpart: &str) -> Result<(), anyhow::Error> {
        #[derive(Serialize)]
        struct Request {
            localpart: String,
            password: String, // Required by the API but not used in this context
        }

        let body = Request {
            localpart: localpart.to_owned(),
            password: String::new(), // Empty password since we're using admin auth
        };

        let response = self
            .post("_synapse/mas/allow_cross_signing_reset")
            .json(&body)
            .send_traced()
            .await
            .context("Failed to allow cross-signing reset in Synapse")?;

        response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while allowing cross-signing reset in Synapse")?;

        Ok(())
    }
}
