// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashSet, time::Duration};

use anyhow::{Context, bail};
use http::{Method, StatusCode};
use mas_http::RequestBuilderExt as _;
use mas_matrix::{HomeserverConnection, MatrixUser, ProvisionRequest};
use serde::{Deserialize, Serialize};
use tracing::debug;
use url::Url;

use crate::error::{M_EXCLUSIVE, M_INVALID_USERNAME, M_USER_IN_USE, SynapseResponseExt};

static SYNAPSE_AUTH_PROVIDER: &str = "oauth-delegated";

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

    fn put(&self, url: &str) -> reqwest::RequestBuilder {
        self.builder(Method::PUT, url)
    }

    fn delete(&self, url: &str) -> reqwest::RequestBuilder {
        self.builder(Method::DELETE, url)
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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    dehydrated: Option<bool>,
}

#[derive(Serialize)]
struct SynapseUpdateDeviceRequest<'a> {
    display_name: Option<&'a str>,
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
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);

        let response = self
            .get(&format!("_synapse/admin/v2/users/{encoded_mxid}"))
            .send_traced()
            .await
            .context("Failed to query user from Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while querying user from Synapse")?;

        let body: SynapseUser = response
            .json()
            .await
            .context("Failed to deserialize response while querying user from Synapse")?;

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
    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, anyhow::Error> {
        // Synapse will give us a M_UNKNOWN error if the localpart is not ASCII,
        // so we bail out early
        if !localpart.is_ascii() {
            return Ok(false);
        }

        let localpart = urlencoding::encode(localpart);

        let response = self
            .get(&format!(
                "_synapse/admin/v1/username_available?username={localpart}"
            ))
            .send_traced()
            .await
            .context("Failed to query localpart availability from Synapse")?;

        match response.error_for_synapse_error().await {
            Ok(resp) => {
                let response: UsernameAvailableResponse = resp.json().await.context(
                    "Unexpected response while querying localpart availability from Synapse",
                )?;

                Ok(response.available)
            }

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
        name = "homeserver.provision_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = request.localpart(),
            user.id = request.sub(),
        ),
        err(Debug),
    )]
    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, anyhow::Error> {
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

        let mxid = self.mxid(request.localpart());
        let encoded_mxid = urlencoding::encode(&mxid);
        let response = self
            .put(&format!("_synapse/admin/v2/users/{encoded_mxid}"))
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
            code => bail!("Unexpected HTTP code while provisioning user in Synapse: {code}"),
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
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);

        let response = self
            .post(&format!("_synapse/admin/v2/users/{encoded_mxid}/devices"))
            .json(&SynapseDevice {
                device_id: device_id.to_owned(),
                dehydrated: None,
            })
            .send_traced()
            .await
            .context("Failed to create device in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while creating device in Synapse")?;

        if response.status() != StatusCode::CREATED {
            bail!(
                "Unexpected HTTP code while creating device in Synapse: {}",
                response.status()
            );
        }

        // It's annoying, but the POST endpoint doesn't let us set the display name
        // of the device, so we have to do it manually.
        if let Some(display_name) = initial_display_name {
            self.update_device_display_name(localpart, device_id, display_name)
                .await?;
        }

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
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);
        let device_id = urlencoding::encode(device_id);
        let response = self
            .put(&format!(
                "_synapse/admin/v2/users/{encoded_mxid}/devices/{device_id}"
            ))
            .json(&SynapseUpdateDeviceRequest {
                display_name: Some(display_name),
            })
            .send_traced()
            .await
            .context("Failed to update device display name in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while updating device display name in Synapse")?;

        if response.status() != StatusCode::OK {
            bail!(
                "Unexpected HTTP code while updating device display name in Synapse: {}",
                response.status()
            );
        }

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
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);
        let encoded_device_id = urlencoding::encode(device_id);

        let response = self
            .delete(&format!(
                "_synapse/admin/v2/users/{encoded_mxid}/devices/{encoded_device_id}"
            ))
            .send_traced()
            .await
            .context("Failed to delete device in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while deleting device in Synapse")?;

        if response.status() != StatusCode::OK {
            bail!(
                "Unexpected HTTP code while deleting device in Synapse: {}",
                response.status()
            );
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.sync_devices",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Debug),
    )]
    async fn sync_devices(
        &self,
        localpart: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        // Get the list of current devices
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);

        let response = self
            .get(&format!("_synapse/admin/v2/users/{encoded_mxid}/devices"))
            .send_traced()
            .await
            .context("Failed to query devices from Synapse")?;

        let response = response.error_for_synapse_error().await?;

        if response.status() != StatusCode::OK {
            bail!(
                "Unexpected HTTP code while querying devices from Synapse: {}",
                response.status()
            );
        }

        let body: SynapseDeviceListResponse = response
            .json()
            .await
            .context("Failed to parse response while querying devices from Synapse")?;

        let existing_devices: HashSet<String> = body
            .devices
            .into_iter()
            .filter(|d| d.dehydrated != Some(true))
            .map(|d| d.device_id)
            .collect();

        // First, delete all the devices that are not needed anymore
        let to_delete = existing_devices.difference(&devices).cloned().collect();

        let response = self
            .post(&format!(
                "_synapse/admin/v2/users/{encoded_mxid}/delete_devices"
            ))
            .json(&SynapseDeleteDevicesRequest { devices: to_delete })
            .send_traced()
            .await
            .context("Failed to delete devices from Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while deleting devices from Synapse")?;

        if response.status() != StatusCode::OK {
            bail!(
                "Unexpected HTTP code while deleting devices from Synapse: {}",
                response.status()
            );
        }

        // Then, create the devices that are missing. There is no batching API to do
        // this, so we do this sequentially, which is fine as the API is idempotent.
        for device_id in devices.difference(&existing_devices) {
            self.upsert_device(localpart, device_id, None).await?;
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.delete_user",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
            erase = erase,
        ),
        err(Debug),
    )]
    async fn delete_user(&self, localpart: &str, erase: bool) -> Result<(), anyhow::Error> {
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);

        let response = self
            .post(&format!("_synapse/admin/v1/deactivate/{encoded_mxid}"))
            .json(&SynapseDeactivateUserRequest { erase })
            // Deactivation can take a while, so we set a longer timeout
            .timeout(Duration::from_secs(60 * 5))
            .send_traced()
            .await
            .context("Failed to deactivate user in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while deactivating user in Synapse")?;

        if response.status() != StatusCode::OK {
            bail!(
                "Unexpected HTTP code while deactivating user in Synapse: {}",
                response.status()
            );
        }

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
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);
        let response = self
            .put(&format!("_synapse/admin/v2/users/{encoded_mxid}"))
            .json(&SynapseUser {
                deactivated: Some(false),
                ..SynapseUser::default()
            })
            .send_traced()
            .await
            .context("Failed to reactivate user in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while reactivating user in Synapse")?;

        match response.status() {
            StatusCode::CREATED | StatusCode::OK => Ok(()),
            code => bail!("Unexpected HTTP code while reactivating user in Synapse: {code}",),
        }
    }

    #[tracing::instrument(
        name = "homeserver.set_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
            matrix.displayname = displayname,
        ),
        err(Debug),
    )]
    async fn set_displayname(
        &self,
        localpart: &str,
        displayname: &str,
    ) -> Result<(), anyhow::Error> {
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);
        let response = self
            .put(&format!(
                "_matrix/client/v3/profile/{encoded_mxid}/displayname"
            ))
            .json(&SetDisplayNameRequest { displayname })
            .send_traced()
            .await
            .context("Failed to set displayname in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while setting displayname in Synapse")?;

        if response.status() != StatusCode::OK {
            bail!(
                "Unexpected HTTP code while setting displayname in Synapse: {}",
                response.status()
            );
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "homeserver.unset_displayname",
        skip_all,
        fields(
            matrix.homeserver = self.homeserver,
            matrix.localpart = localpart,
        ),
        err(Display),
    )]
    async fn unset_displayname(&self, localpart: &str) -> Result<(), anyhow::Error> {
        self.set_displayname(localpart, "").await
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
        let mxid = self.mxid(localpart);
        let encoded_mxid = urlencoding::encode(&mxid);

        let response = self
            .post(&format!(
                "_synapse/admin/v1/users/{encoded_mxid}/_allow_cross_signing_replacement_without_uia"
            ))
            .json(&SynapseAllowCrossSigningResetRequest {})
            .send_traced()
            .await
            .context("Failed to allow cross-signing reset in Synapse")?;

        let response = response
            .error_for_synapse_error()
            .await
            .context("Unexpected HTTP response while allowing cross-signing reset in Synapse")?;

        if response.status() != StatusCode::OK {
            bail!(
                "Unexpected HTTP code while allowing cross-signing reset in Synapse: {}",
                response.status(),
            );
        }

        Ok(())
    }
}
