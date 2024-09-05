// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![allow(clippy::blocks_in_conditions)]

use std::collections::HashSet;

use anyhow::{bail, Context};
use http::{header::AUTHORIZATION, request::Builder, Method, Request, StatusCode};
use mas_axum_utils::http_client_factory::HttpClientFactory;
use mas_http::{catch_http_codes, json_response, EmptyBody, HttpServiceExt};
use mas_matrix::{HomeserverConnection, MatrixUser, ProvisionRequest};
use serde::{Deserialize, Serialize};
use tower::{Service, ServiceExt};
use tracing::debug;
use url::Url;

use self::error::catch_homeserver_error;

static SYNAPSE_AUTH_PROVIDER: &str = "oauth-delegated";

/// Encountered when trying to register a user ID which has been taken.
/// — <https://spec.matrix.org/v1.10/client-server-api/#other-error-codes>
const M_USER_IN_USE: &str = "M_USER_IN_USE";
/// Encountered when trying to register a user ID which is not valid.
/// — <https://spec.matrix.org/v1.10/client-server-api/#other-error-codes>
const M_INVALID_USERNAME: &str = "M_INVALID_USERNAME";

mod error;

#[derive(Clone)]
pub struct SynapseConnection {
    homeserver: String,
    endpoint: Url,
    access_token: String,
    http_client_factory: HttpClientFactory,
}

impl SynapseConnection {
    #[must_use]
    pub fn new(
        homeserver: String,
        endpoint: Url,
        access_token: String,
        http_client_factory: HttpClientFactory,
    ) -> Self {
        Self {
            homeserver,
            endpoint,
            access_token,
            http_client_factory,
        }
    }

    fn builder(&self, url: &str) -> Builder {
        Request::builder()
            .uri(
                self.endpoint
                    .join(url)
                    .map(String::from)
                    .unwrap_or_default(),
            )
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
    }

    #[must_use]
    pub fn post(&self, url: &str) -> Builder {
        self.builder(url).method(Method::POST)
    }

    #[must_use]
    pub fn get(&self, url: &str) -> Builder {
        self.builder(url).method(Method::GET)
    }

    #[must_use]
    pub fn put(&self, url: &str) -> Builder {
        self.builder(url).method(Method::PUT)
    }

    #[must_use]
    pub fn delete(&self, url: &str) -> Builder {
        self.builder(url).method(Method::DELETE)
    }
}

#[derive(Serialize, Deserialize)]
struct ExternalID {
    auth_provider: String,
    external_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ThreePIDMedium {
    Email,
    Msisdn,
}

#[derive(Serialize, Deserialize)]
struct ThreePID {
    medium: ThreePIDMedium,
    address: String,
}

#[derive(Default, Serialize, Deserialize)]
struct SynapseUser {
    #[serde(
        default,
        rename = "displayname",
        skip_serializing_if = "Option::is_none"
    )]
    display_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    avatar_url: Option<String>,

    #[serde(default, rename = "threepids", skip_serializing_if = "Option::is_none")]
    three_pids: Option<Vec<ThreePID>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_ids: Option<Vec<ExternalID>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    deactivated: Option<bool>,
}

#[derive(Deserialize)]
struct SynapseDeviceListResponse {
    devices: Vec<SynapseDevice>,
}

#[derive(Serialize, Deserialize)]
struct SynapseDevice {
    device_id: String,
}

#[derive(Serialize)]
struct SynapseDeleteDevicesRequest {
    devices: Vec<String>,
}

#[derive(Serialize)]
struct SetDisplayNameRequest<'a> {
    displayname: &'a str,
}

#[derive(Serialize)]
struct SynapseDeactivateUserRequest {
    erase: bool,
}

#[derive(Serialize)]
struct SynapseAllowCrossSigningResetRequest {}

/// Response body of
/// `/_synapse/admin/v1/username_available?username={localpart}`
#[derive(Deserialize)]
struct UsernameAvailableResponse {
    available: bool,
}

#[async_trait::async_trait]
impl HomeserverConnection for SynapseConnection {
    type Error = anyhow::Error;

    fn homeserver(&self) -> &str {
        &self.homeserver
    }

    #[tracing::instrument(
        name = "homeserver.query_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Debug),
    )]
    async fn query_user(&self, mxid: &str) -> Result<MatrixUser, Self::Error> {
        let mxid = urlencoding::encode(mxid);
        let mut client = self
            .http_client_factory
            .client("homeserver.query_user")
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error)
            .json_response();

        let request = self
            .get(&format!("_synapse/admin/v2/users/{mxid}"))
            .body(EmptyBody::new())?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to query user from Synapse")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to query user from Synapse"));
        }

        let body: SynapseUser = response.into_body();

        Ok(MatrixUser {
            displayname: body.display_name,
            avatar_url: body.avatar_url,
            deactivated: body.deactivated.unwrap_or(false),
        })
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
    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, Self::Error> {
        let localpart = urlencoding::encode(localpart);
        let mut client = self
            .http_client_factory
            .client("homeserver.is_localpart_available")
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error)
            .json_response::<UsernameAvailableResponse>();

        let request = self
            .get(&format!(
                "_synapse/admin/v1/username_available?username={localpart}"
            ))
            .body(EmptyBody::new())?;

        let response = client.ready().await?.call(request).await;

        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    // We should have already handled 4xx and 5xx errors by this point
                    // so anything not 2xx is fairly weird
                    bail!(
                        "unexpected response from /username_available: {}",
                        resp.status()
                    );
                }
                Ok(resp.into_body().available)
            }
            Err(err) => match err {
                // Convoluted as... but we want to handle some of the 400 Bad Request responses
                // ourselves
                json_response::Error::Service {
                    inner:
                        catch_http_codes::Error::HttpError {
                            status_code: StatusCode::BAD_REQUEST,
                            inner: homeserver_error,
                        },
                } if homeserver_error.errcode() == Some(M_INVALID_USERNAME)
                    || homeserver_error.errcode() == Some(M_USER_IN_USE) =>
                {
                    debug!("Username not available: {homeserver_error}");
                    Ok(false)
                }

                other_err => Err(anyhow::Error::new(other_err)
                    .context("Failed to query localpart availability from Synapse")),
            },
        }
    }

    #[tracing::instrument(
        name = "homeserver.provision_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = request.mxid(),
            user.id = request.sub(),
        ),
        err(Debug),
    )]
    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, Self::Error> {
        let mut body = SynapseUser {
            external_ids: Some(vec![ExternalID {
                auth_provider: SYNAPSE_AUTH_PROVIDER.to_owned(),
                external_id: request.sub().to_owned(),
            }]),
            ..SynapseUser::default()
        };

        request
            .on_displayname(|displayname| {
                body.display_name = Some(displayname.unwrap_or_default().to_owned());
            })
            .on_avatar_url(|avatar_url| {
                body.avatar_url = Some(avatar_url.unwrap_or_default().to_owned());
            })
            .on_emails(|emails| {
                body.three_pids = Some(
                    emails
                        .unwrap_or_default()
                        .iter()
                        .map(|email| ThreePID {
                            medium: ThreePIDMedium::Email,
                            address: email.clone(),
                        })
                        .collect(),
                );
            });

        let mut client = self
            .http_client_factory
            .client("homeserver.provision_user")
            .request_bytes_to_body()
            .json_request()
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error);

        let mxid = urlencoding::encode(request.mxid());
        let request = self
            .put(&format!("_synapse/admin/v2/users/{mxid}"))
            .body(body)?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to provision user in Synapse")?;

        match response.status() {
            StatusCode::CREATED => Ok(true),
            StatusCode::OK => Ok(false),
            code => Err(anyhow::anyhow!(
                "Failed to provision user in Synapse: {}",
                code
            )),
        }
    }

    #[tracing::instrument(
        name = "homeserver.create_device",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            matrix.device_id = device_id,
        ),
        err(Debug),
    )]
    async fn create_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        let mxid = urlencoding::encode(mxid);
        let mut client = self
            .http_client_factory
            .client("homeserver.create_device")
            .request_bytes_to_body()
            .json_request()
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error);

        let request = self
            .post(&format!("_synapse/admin/v2/users/{mxid}/devices"))
            .body(SynapseDevice {
                device_id: device_id.to_owned(),
            })?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to create device in Synapse")?;

        if response.status() != StatusCode::CREATED {
            return Err(anyhow::anyhow!("Failed to create device in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.delete_device",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            matrix.device_id = device_id,
        ),
        err(Debug),
    )]
    async fn delete_device(&self, mxid: &str, device_id: &str) -> Result<(), Self::Error> {
        let mxid = urlencoding::encode(mxid);
        let device_id = urlencoding::encode(device_id);
        let mut client = self
            .http_client_factory
            .client("homeserver.delete_device")
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error);

        let request = self
            .delete(&format!(
                "_synapse/admin/v2/users/{mxid}/devices/{device_id}"
            ))
            .body(EmptyBody::new())?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to delete device in Synapse")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to delete device in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.sync_devices",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Debug),
    )]
    async fn sync_devices(&self, mxid: &str, devices: HashSet<String>) -> Result<(), Self::Error> {
        // Get the list of current devices
        let mxid_url = urlencoding::encode(mxid);
        let mut client = self
            .http_client_factory
            .client("homeserver.sync_devices.query")
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error)
            .json_response();

        let request = self
            .get(&format!("_synapse/admin/v2/users/{mxid_url}/devices"))
            .body(EmptyBody::new())?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to query user from Synapse")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to query user devices from Synapse"));
        }

        let body: SynapseDeviceListResponse = response.into_body();

        let existing_devices: HashSet<String> =
            body.devices.into_iter().map(|d| d.device_id).collect();

        // First, delete all the devices that are not needed anymore
        let to_delete = existing_devices.difference(&devices).cloned().collect();

        let mut client = self
            .http_client_factory
            .client("homeserver.sync_devices.delete")
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error)
            .request_bytes_to_body()
            .json_request();

        let request = self
            .post(&format!(
                "_synapse/admin/v2/users/{mxid_url}/delete_devices"
            ))
            .body(SynapseDeleteDevicesRequest { devices: to_delete })?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to query user from Synapse")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to delete devices from Synapse"));
        }

        // Then, create the devices that are missing. There is no batching API to do
        // this, so we do this sequentially, which is fine as the API is idempotent.
        for device_id in devices.difference(&existing_devices) {
            self.create_device(mxid, device_id).await?;
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.delete_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            erase = erase,
        ),
        err(Debug),
    )]
    async fn delete_user(&self, mxid: &str, erase: bool) -> Result<(), Self::Error> {
        let mxid = urlencoding::encode(mxid);
        let mut client = self
            .http_client_factory
            .client("homeserver.delete_user")
            .request_bytes_to_body()
            .json_request()
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error);

        let request = self
            .post(&format!("_synapse/admin/v1/deactivate/{mxid}"))
            .body(SynapseDeactivateUserRequest { erase })?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to delete user in Synapse")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to delete user in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.reactivate_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Debug),
    )]
    async fn reactivate_user(&self, mxid: &str) -> Result<(), anyhow::Error> {
        let body = SynapseUser {
            deactivated: Some(false),
            ..SynapseUser::default()
        };

        let mut client = self
            .http_client_factory
            .client("homeserver.reactivate_user")
            .request_bytes_to_body()
            .json_request()
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error);

        let mxid = urlencoding::encode(mxid);
        let request = self
            .put(&format!("_synapse/admin/v2/users/{mxid}"))
            .body(body)?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to provision user in Synapse")?;

        match response.status() {
            StatusCode::CREATED | StatusCode::OK => Ok(()),
            code => Err(anyhow::anyhow!(
                "Failed to provision user in Synapse: {}",
                code
            )),
        }
    }

    #[tracing::instrument(
        name = "homeserver.set_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
            matrix.displayname = displayname,
        ),
        err(Debug),
    )]
    async fn set_displayname(&self, mxid: &str, displayname: &str) -> Result<(), Self::Error> {
        let mxid = urlencoding::encode(mxid);
        let mut client = self
            .http_client_factory
            .client("homeserver.set_displayname")
            .request_bytes_to_body()
            .json_request()
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error);

        let request = self
            .put(&format!("_matrix/client/v3/profile/{mxid}/displayname"))
            .body(SetDisplayNameRequest { displayname })?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to set displayname in Synapse")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!("Failed to set displayname in Synapse"));
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.unset_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Display),
    )]
    async fn unset_displayname(&self, mxid: &str) -> Result<(), Self::Error> {
        self.set_displayname(mxid, "").await
    }

    #[tracing::instrument(
        name = "homeserver.allow_cross_signing_reset",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.mxid = mxid,
        ),
        err(Debug),
    )]
    async fn allow_cross_signing_reset(&self, mxid: &str) -> Result<(), Self::Error> {
        let mxid = urlencoding::encode(mxid);
        let mut client = self
            .http_client_factory
            .client("homeserver.allow_cross_signing_reset")
            .request_bytes_to_body()
            .json_request()
            .response_body_to_bytes()
            .catch_http_errors(catch_homeserver_error);

        let request = self
            .post(&format!(
                "_synapse/admin/v1/users/{mxid}/_allow_cross_signing_replacement_without_uia"
            ))
            .body(SynapseAllowCrossSigningResetRequest {})?;

        let response = client
            .ready()
            .await?
            .call(request)
            .await
            .context("Failed to allow cross-signing reset in Synapse")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!(
                "Failed to allow cross signing reset in Synapse: {}",
                response.status()
            ));
        }

        Ok(())
    }
}
