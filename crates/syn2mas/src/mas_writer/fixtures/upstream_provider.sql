INSERT INTO upstream_oauth_providers
  (
    upstream_oauth_provider_id,
    scope,
    client_id,
    token_endpoint_auth_method,
    created_at
  )
  VALUES
  (
    '00000000-0000-0000-0000-000000000004',
    'openid',
    'someClientId',
    'client_secret_basic',
    '2011-12-13 14:15:16Z'
  );
