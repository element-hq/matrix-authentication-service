// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing the PostgreSQL implementation of the repositories
//! related to the upstream OAuth 2.0 providers

mod link;
mod provider;
mod session;

pub use self::{
    link::PgUpstreamOAuthLinkRepository, provider::PgUpstreamOAuthProviderRepository,
    session::PgUpstreamOAuthSessionRepository,
};

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_storage::{
        Pagination, RepositoryAccess,
        clock::MockClock,
        upstream_oauth2::{
            UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository, UpstreamOAuthProviderFilter,
            UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
            UpstreamOAuthSessionRepository,
        },
        user::UserRepository,
    };
    use oauth2_types::scope::{OPENID, Scope};
    use rand::SeedableRng;
    use sqlx::PgPool;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_repository(pool: PgPool) {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap();

        // The provider list should be empty at the start
        let all_providers = repo.upstream_oauth_provider().all_enabled().await.unwrap();
        assert!(all_providers.is_empty());

        // Let's add a provider
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://example.com/".to_owned()),
                    human_name: None,
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    token_endpoint_signing_alg: None,
                    client_id: "client-id".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    token_endpoint_override: None,
                    authorization_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                },
            )
            .await
            .unwrap();

        // Look it up in the database
        let provider = repo
            .upstream_oauth_provider()
            .lookup(provider.id)
            .await
            .unwrap()
            .expect("provider to be found in the database");
        assert_eq!(provider.issuer.as_deref(), Some("https://example.com/"));
        assert_eq!(provider.client_id, "client-id");

        // It should be in the list of all providers
        let providers = repo.upstream_oauth_provider().all_enabled().await.unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].issuer.as_deref(), Some("https://example.com/"));
        assert_eq!(providers[0].client_id, "client-id");

        // Start a session
        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &clock,
                &provider,
                "some-state".to_owned(),
                None,
                "some-nonce".to_owned(),
            )
            .await
            .unwrap();

        // Look it up in the database
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("session to be found in the database");
        assert_eq!(session.provider_id, provider.id);
        assert_eq!(session.link_id(), None);
        assert!(session.is_pending());
        assert!(!session.is_completed());
        assert!(!session.is_consumed());

        // Create a link
        let link = repo
            .upstream_oauth_link()
            .add(&mut rng, &clock, &provider, "a-subject".to_owned(), None)
            .await
            .unwrap();

        // We can look it up by its ID
        repo.upstream_oauth_link()
            .lookup(link.id)
            .await
            .unwrap()
            .expect("link to be found in database");

        // or by its subject
        let link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, "a-subject")
            .await
            .unwrap()
            .expect("link to be found in database");
        assert_eq!(link.subject, "a-subject");
        assert_eq!(link.provider_id, provider.id);

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(&clock, session, &link, None, None, None)
            .await
            .unwrap();
        // Reload the session
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("session to be found in the database");
        assert!(session.is_completed());
        assert!(!session.is_consumed());
        assert_eq!(session.link_id(), Some(link.id));

        let session = repo
            .upstream_oauth_session()
            .consume(&clock, session)
            .await
            .unwrap();
        // Reload the session
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("session to be found in the database");
        assert!(session.is_consumed());

        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await
            .unwrap();

        // XXX: we should also try other combinations of the filter
        let filter = UpstreamOAuthLinkFilter::new()
            .for_user(&user)
            .for_provider(&provider)
            .for_subject("a-subject")
            .enabled_providers_only();

        let links = repo
            .upstream_oauth_link()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert!(!links.has_previous_page);
        assert!(!links.has_next_page);
        assert_eq!(links.edges.len(), 1);
        assert_eq!(links.edges[0].id, link.id);
        assert_eq!(links.edges[0].user_id, Some(user.id));

        assert_eq!(repo.upstream_oauth_link().count(filter).await.unwrap(), 1);

        // There should be exactly one enabled provider
        assert_eq!(
            repo.upstream_oauth_provider()
                .count(UpstreamOAuthProviderFilter::new())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repo.upstream_oauth_provider()
                .count(UpstreamOAuthProviderFilter::new().enabled_only())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repo.upstream_oauth_provider()
                .count(UpstreamOAuthProviderFilter::new().disabled_only())
                .await
                .unwrap(),
            0
        );

        // Disable the provider
        repo.upstream_oauth_provider()
            .disable(&clock, provider.clone())
            .await
            .unwrap();

        // There should be exactly one disabled provider
        assert_eq!(
            repo.upstream_oauth_provider()
                .count(UpstreamOAuthProviderFilter::new())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repo.upstream_oauth_provider()
                .count(UpstreamOAuthProviderFilter::new().enabled_only())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            repo.upstream_oauth_provider()
                .count(UpstreamOAuthProviderFilter::new().disabled_only())
                .await
                .unwrap(),
            1
        );

        // Try deleting the provider
        repo.upstream_oauth_provider()
            .delete(provider)
            .await
            .unwrap();
        assert_eq!(
            repo.upstream_oauth_provider()
                .count(UpstreamOAuthProviderFilter::new())
                .await
                .unwrap(),
            0
        );
    }

    /// Test that the pagination works as expected in the upstream OAuth
    /// provider repository
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_provider_repository_pagination(pool: PgPool) {
        let scope = Scope::from_iter([OPENID]);

        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap();

        let filter = UpstreamOAuthProviderFilter::new();

        // Count the number of providers before we start
        assert_eq!(
            repo.upstream_oauth_provider().count(filter).await.unwrap(),
            0
        );

        let mut ids = Vec::with_capacity(20);
        // Create 20 providers
        for idx in 0..20 {
            let client_id = format!("client-{idx}");
            let provider = repo
                .upstream_oauth_provider()
                .add(
                    &mut rng,
                    &clock,
                    UpstreamOAuthProviderParams {
                        issuer: None,
                        human_name: None,
                        brand_name: None,
                        scope: scope.clone(),
                        token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                        fetch_userinfo: false,
                        userinfo_signed_response_alg: None,
                        token_endpoint_signing_alg: None,
                        id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                        client_id,
                        encrypted_client_secret: None,
                        claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                        token_endpoint_override: None,
                        authorization_endpoint_override: None,
                        userinfo_endpoint_override: None,
                        jwks_uri_override: None,
                        discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                        pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                        response_mode: None,
                        additional_authorization_parameters: Vec::new(),
                        forward_login_hint: false,
                        ui_order: 0,
                    },
                )
                .await
                .unwrap();
            ids.push(provider.id);
            clock.advance(Duration::microseconds(10 * 1000 * 1000));
        }

        // Now we have 20 providers
        assert_eq!(
            repo.upstream_oauth_provider().count(filter).await.unwrap(),
            20
        );

        // Lookup the first 10 items
        let page = repo
            .upstream_oauth_provider()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();

        // It returned the first 10 items
        assert!(page.has_next_page);
        let edge_ids: Vec<_> = page.edges.iter().map(|p| p.id).collect();
        assert_eq!(&edge_ids, &ids[..10]);

        // Getting the same page with the "enabled only" filter should return the same
        // results
        let other_page = repo
            .upstream_oauth_provider()
            .list(filter.enabled_only(), Pagination::first(10))
            .await
            .unwrap();

        assert_eq!(page, other_page);

        // Lookup the next 10 items
        let page = repo
            .upstream_oauth_provider()
            .list(filter, Pagination::first(10).after(ids[9]))
            .await
            .unwrap();

        // It returned the next 10 items
        assert!(!page.has_next_page);
        let edge_ids: Vec<_> = page.edges.iter().map(|p| p.id).collect();
        assert_eq!(&edge_ids, &ids[10..]);

        // Lookup the last 10 items
        let page = repo
            .upstream_oauth_provider()
            .list(filter, Pagination::last(10))
            .await
            .unwrap();

        // It returned the last 10 items
        assert!(page.has_previous_page);
        let edge_ids: Vec<_> = page.edges.iter().map(|p| p.id).collect();
        assert_eq!(&edge_ids, &ids[10..]);

        // Lookup the previous 10 items
        let page = repo
            .upstream_oauth_provider()
            .list(filter, Pagination::last(10).before(ids[10]))
            .await
            .unwrap();

        // It returned the previous 10 items
        assert!(!page.has_previous_page);
        let edge_ids: Vec<_> = page.edges.iter().map(|p| p.id).collect();
        assert_eq!(&edge_ids, &ids[..10]);

        // Lookup 10 items between two IDs
        let page = repo
            .upstream_oauth_provider()
            .list(filter, Pagination::first(10).after(ids[5]).before(ids[8]))
            .await
            .unwrap();

        // It returned the items in between
        assert!(!page.has_next_page);
        let edge_ids: Vec<_> = page.edges.iter().map(|p| p.id).collect();
        assert_eq!(&edge_ids, &ids[6..8]);

        // There should not be any disabled providers
        assert!(
            repo.upstream_oauth_provider()
                .list(
                    UpstreamOAuthProviderFilter::new().disabled_only(),
                    Pagination::first(1)
                )
                .await
                .unwrap()
                .edges
                .is_empty()
        );
    }
}
