// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{MatrixUser, ProvisionRequest};

struct MockUser {
    sub: String,
    avatar_url: Option<String>,
    displayname: Option<String>,
    devices: HashSet<String>,
    emails: Option<Vec<String>>,
    cross_signing_reset_allowed: bool,
    deactivated: bool,
}

/// A mock implementation of a [`HomeserverConnection`], which never fails and
/// doesn't do anything.
pub struct HomeserverConnection {
    homeserver: String,
    users: RwLock<HashMap<String, MockUser>>,
    reserved_localparts: RwLock<HashSet<&'static str>>,
}

impl HomeserverConnection {
    /// Create a new mock connection.
    pub fn new<H>(homeserver: H) -> Self
    where
        H: Into<String>,
    {
        Self {
            homeserver: homeserver.into(),
            users: RwLock::new(HashMap::new()),
            reserved_localparts: RwLock::new(HashSet::new()),
        }
    }

    pub async fn reserve_localpart(&self, localpart: &'static str) {
        self.reserved_localparts.write().await.insert(localpart);
    }
}

#[async_trait]
impl crate::HomeserverConnection for HomeserverConnection {
    fn homeserver(&self) -> &str {
        &self.homeserver
    }

    async fn query_user(&self, mxid: &str) -> Result<MatrixUser, anyhow::Error> {
        let users = self.users.read().await;
        let user = users.get(mxid).context("User not found")?;
        Ok(MatrixUser {
            displayname: user.displayname.clone(),
            avatar_url: user.avatar_url.clone(),
            deactivated: user.deactivated,
        })
    }

    async fn provision_user(&self, request: &ProvisionRequest) -> Result<bool, anyhow::Error> {
        let mut users = self.users.write().await;
        let inserted = !users.contains_key(request.mxid());
        let user = users.entry(request.mxid().to_owned()).or_insert(MockUser {
            sub: request.sub().to_owned(),
            avatar_url: None,
            displayname: None,
            devices: HashSet::new(),
            emails: None,
            cross_signing_reset_allowed: false,
            deactivated: false,
        });

        anyhow::ensure!(
            user.sub == request.sub(),
            "User already provisioned with different sub"
        );

        request.on_emails(|emails| {
            user.emails = emails.map(ToOwned::to_owned);
        });

        request.on_displayname(|displayname| {
            user.displayname = displayname.map(ToOwned::to_owned);
        });

        request.on_avatar_url(|avatar_url| {
            user.avatar_url = avatar_url.map(ToOwned::to_owned);
        });

        Ok(inserted)
    }

    async fn is_localpart_available(&self, localpart: &str) -> Result<bool, anyhow::Error> {
        if self.reserved_localparts.read().await.contains(localpart) {
            return Ok(false);
        }

        let mxid = self.mxid(localpart);
        let users = self.users.read().await;
        Ok(!users.contains_key(&mxid))
    }

    async fn create_device(
        &self,
        mxid: &str,
        device_id: &str,
        _initial_display_name: Option<&str>,
    ) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.devices.insert(device_id.to_owned());
        Ok(())
    }

    async fn update_device_display_name(
        &self,
        mxid: &str,
        device_id: &str,
        _display_name: &str,
    ) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.devices.get(device_id).context("Device not found")?;
        Ok(())
    }

    async fn delete_device(&self, mxid: &str, device_id: &str) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.devices.remove(device_id);
        Ok(())
    }

    async fn sync_devices(
        &self,
        mxid: &str,
        devices: HashSet<String>,
    ) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.devices = devices;
        Ok(())
    }

    async fn delete_user(&self, mxid: &str, erase: bool) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.devices.clear();
        user.emails = None;
        user.deactivated = true;
        if erase {
            user.avatar_url = None;
            user.displayname = None;
        }

        Ok(())
    }

    async fn reactivate_user(&self, mxid: &str) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.deactivated = false;

        Ok(())
    }

    async fn set_displayname(&self, mxid: &str, displayname: &str) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.displayname = Some(displayname.to_owned());
        Ok(())
    }

    async fn unset_displayname(&self, mxid: &str) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.displayname = None;
        Ok(())
    }

    async fn allow_cross_signing_reset(&self, mxid: &str) -> Result<(), anyhow::Error> {
        let mut users = self.users.write().await;
        let user = users.get_mut(mxid).context("User not found")?;
        user.cross_signing_reset_allowed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HomeserverConnection as _;

    #[tokio::test]
    async fn test_mock_connection() {
        let conn = HomeserverConnection::new("example.org");

        let mxid = "@test:example.org";
        let device = "test";
        assert_eq!(conn.homeserver(), "example.org");
        assert_eq!(conn.mxid("test"), mxid);

        assert!(conn.query_user(mxid).await.is_err());
        assert!(conn.create_device(mxid, device, None).await.is_err());
        assert!(conn.delete_device(mxid, device).await.is_err());

        let request = ProvisionRequest::new("@test:example.org", "test")
            .set_displayname("Test User".into())
            .set_avatar_url("mxc://example.org/1234567890".into())
            .set_emails(vec!["test@example.org".to_owned()]);

        let inserted = conn.provision_user(&request).await.unwrap();
        assert!(inserted);

        let user = conn.query_user(mxid).await.unwrap();
        assert_eq!(user.displayname, Some("Test User".into()));
        assert_eq!(user.avatar_url, Some("mxc://example.org/1234567890".into()));

        // Set the displayname again
        assert!(conn.set_displayname(mxid, "John").await.is_ok());

        let user = conn.query_user(mxid).await.unwrap();
        assert_eq!(user.displayname, Some("John".into()));

        // Unset the displayname
        assert!(conn.unset_displayname(mxid).await.is_ok());

        let user = conn.query_user(mxid).await.unwrap();
        assert_eq!(user.displayname, None);

        // Deleting a non-existent device should not fail
        assert!(conn.delete_device(mxid, device).await.is_ok());

        // Create the device
        assert!(conn.create_device(mxid, device, None).await.is_ok());
        // Create the same device again
        assert!(conn.create_device(mxid, device, None).await.is_ok());

        // XXX: there is no API to query devices yet in the trait
        // Delete the device
        assert!(conn.delete_device(mxid, device).await.is_ok());

        // The user we just created should be not available
        assert!(!conn.is_localpart_available("test").await.unwrap());
        // But another user should be
        assert!(conn.is_localpart_available("alice").await.unwrap());

        // Reserve the localpart, it should not be available anymore
        conn.reserve_localpart("alice").await;
        assert!(!conn.is_localpart_available("alice").await.unwrap());
    }
}
