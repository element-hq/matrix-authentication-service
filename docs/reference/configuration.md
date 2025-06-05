# Configuration file reference

## `http`

Controls the web server.

```yaml
http:
  # Public URL base used when building absolute public URLs
  public_base: https://auth.example.com/

  # OIDC issuer advertised by the service. Defaults to `public_base`
  issuer: https://example.com/

  # List of HTTP listeners, see below
  listeners:
    # ...
```

### `http.listeners`

Each listener can serve multiple resources, and listen on multiple TCP ports or UNIX sockets.

```yaml
http:
  listeners:
    # The name of the listener, used in logs and metrics
    - name: web

      # List of resources to serve
      resources:
        # Serves the .well-known/openid-configuration document
        - name: discovery
        # Serves the human-facing pages, such as the login page
        - name: human
        # Serves the OAuth 2.0/OIDC endpoints
        - name: oauth
        # Serves the Matrix C-S API compatibility endpoints
        - name: compat
        # Serve the GraphQL API used by the frontend,
        # and optionally the GraphQL playground
        - name: graphql
          playground: true
        # Serve the given folder on the /assets/ path
        - name: assets
          path: ./share/assets/
        # Serve the admin API on the /api/admin/v1/ path. Disabled by default
        #- name: adminapi

      # List of addresses and ports to listen to
      binds:
        # First option: listen to the given address
        - address: "[::]:8080"

        # Second option: listen on the given host and port combination
        - host: localhost
          port: 8081

        # Third option: listen on the given UNIX socket
        - socket: /tmp/mas.sock

        # Fourth option: grab an already open file descriptor given by the parent process
        # This is useful when using systemd socket activation
        - fd: 1
          # Kind of socket that was passed, defaults to tcp
          kind: tcp # or unix

      # Whether to enable the PROXY protocol on the listener
      proxy_protocol: false

      # If set, makes the listener use TLS with the provided certificate and key
      tls:
        #certificate: <inline PEM>
        certificate_file: /path/to/cert.pem
        #key: <inline PEM>
        key_file: /path/to/key.pem
        #password: <password to decrypt the key>
        #password_file: /path/to/password.txt
```

The following additional resources are available, although it is recommended to serve them on a separate listener, not exposed to the public internet:

- `name: prometheus`: serves a Prometheus-compatible metrics endpoint on `/metrics`, if the Prometheus exporter is enabled in `telemetry.metrics.exporter`.
- `name: health`: serves the health check endpoint on `/health`.

## `database`

Configure how to connect to the PostgreSQL database.

MAS must not be connected to a database pooler (such as pgBouncer or pgCat) when it is configured in transaction pooling mode.
See [the relevant section of the database page](database.md#a-warning-about-database-pooling-software) for more information.

```yaml
database:
  # Full connection string as per
  # https://www.postgresql.org/docs/13/libpq-connect.html#id-1.7.3.8.3.6
  uri: postgresql://user:password@hostname:5432/database?sslmode=require

  # -- OR --
  # Separate parameters
  host: hostname
  port: 5432
  #socket:
  username: user
  password: password
  database: database

  # Whether to use SSL to connect to the database
  ssl_mode: require # or disable, prefer, verify-ca, verify-full
  #ssl_ca: # PEM-encoded certificate
  ssl_ca_file: /path/to/ca.pem # Path to the root certificate file

  # Client certificate to present to the server when SSL is enabled
  #ssl_certificate: # PEM-encoded certificate
  ssl_certificate_file: /path/to/cert.pem # Path to the certificate file
  #ssl_key: # PEM-encoded key
  ssl_key_file: /path/to/key.pem # Path to the key file

  # Additional parameters for the connection pool
  min_connections: 0
  max_connections: 10
  connect_timeout: 30
  idle_timeout: 600
  max_lifetime: 1800
```

## `matrix`

Settings related to the connection to the Matrix homeserver

```yaml
matrix:
  # The homeserver name, as per the `server_name` in the Synapse configuration file
  homeserver: example.com

  # Shared secret used to authenticate the service to the homeserver
  # This must be of high entropy, because leaking this secret would allow anyone to perform admin actions on the homeserver
  secret: "SomeRandomSecret"

  # URL to which the homeserver is accessible from the service
  endpoint: "http://localhost:8008"
```

## `templates`

Allows loading custom templates

```yaml
templates:
  # From where to load the templates
  # This is relative to the current working directory, *not* the config file
  path: /to/templates

  # Path to the frontend assets manifest file
  assets_manifest: /to/manifest.json

  # From where to load the translation files
  # Default in Docker distribution: `/usr/local/share/mas-cli/translations/`
  # Default in pre-built binaries: `./share/translations/`
  # Default in locally-built binaries: `./translations/`
  translations_path: /to/translations
```

## `clients`

List of OAuth 2.0/OIDC clients and their keys/secrets. Each `client_id` must be a [ULID](https://github.com/ulid/spec).

```yaml
clients:
  # Confidential client
  - client_id: 000000000000000000000FIRST
    client_auth_method: client_secret_post
    client_secret: secret
    # List of authorized redirect URIs
    redirect_uris:
      - http://localhost:1234/callback
  # Public client
  - client_id: 00000000000000000000SEC0ND
    client_auth_method: none
```

**Note:** any additions or modifications in this list are synced with the database on server startup. Removed entries are only removed with the [`config sync --prune`](../reference/cli/config.md#config-sync---prune---dry-run) command.

## `secrets`

Signing and encryption secrets

```yaml
secrets:
  # Encryption secret (used for encrypting cookies and database fields)
  # This must be a 32-byte long hex-encoded key
  encryption: c7e42fb8baba8f228b2e169fdf4c8216dffd5d33ad18bafd8b928c09ca46c718

  # Signing keys
  keys:
    # It needs at least an RSA key to work properly
    - kid: "ahM2bien"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEAuf28zPUp574jDRdX6uN0d7niZCIUpACFo+Po/13FuIGsrpze
        yMX6CYWVPalgXW9FCrhxL+4toJRy5npjkgsLFsknL5/zXbWKFgt69cMwsWJ9Ra57
        bonSlI7SoCuHhtw7j+sAlHAlqTOCAVz6P039Y/AGvO6xbC7f+9XftWlbbDcjKFcb
        pQilkN9qtkdEH7TLayMAFOsgNvBlwF9+oj9w5PIk3veRTdBXI4GlHjhhzqGZKiRp
        oP9HnycHHveyT+C33vuhQso5a3wcUNuvDVOixSqR4kvSt4UVWNK/KmEQmlWU1/m9
        ClIwrs8Q79q0xkGaSa0iuG60nvm7tZez9TFkxwIDAQABAoIBAHA5YkppQ7fJSm0D
        wNDCHeyABNJWng23IuwZAOXVNxB1bjSOAv8yNgS4zaw/Hx5BnW8yi1lYZb+W0x2u
        i5X7g91j0nkyEi5g88kJdFAGTsM5ok0BUwkHsEBjTUPIACanjGjya48lfBP0OGWK
        LJU2Acbjda1aeUPFpPDXw/w6bieEthQwroq3DHCMnk6i9bsxgIOXeN04ij9XBmsH
        KPCP2hAUnZSlx5febYfHK7/W95aJp22qa//eHS8cKQZCJ0+dQuZwLhlGosTFqLUm
        qhPlt/b1EvPPY0cq5rtUc2W31L0YayVEHVOQx1fQIkH2VIUNbAS+bfVy+o6WCRk6
        s1XDhsECgYEA30tykVTN5LncY4eQIww2mW8v1j1EG6ngVShN3GuBTuXXaEOB8Duc
        yT7yJt1ZhmaJwMk4agmZ1/f/ZXBtfLREGVzVvuwqRZ+LHbqIyhi0wQJA0aezPote
        uTQnFn+IveHGtpQNDYGL/UgkexuCxbc2HOZG51JpunCK0TdtVfO/9OUCgYEA1TuS
        2WAXzNudRG3xd/4OgtkLD9AvfSvyjw2LkwqCMb3A5UEqw7vubk/xgnRvqrAgJRWo
        jndgRrRnikHCavDHBO0GAO/kzrFRfw+e+r4jcLl0Yadke8ndCc7VTnx4wQCrMi5H
        7HEeRwaZONoj5PAPyA5X+N/gT0NNDA7KoQT45DsCgYBt+QWa6A5jaNpPNpPZfwlg
        9e60cAYcLcUri6cVOOk9h1tYoW7cdy+XueWfGIMf+1460Z90MfhP8ncZaY6yzUGA
        0EUBO+Tx10q3wIfgKNzU9hwgZZyU4CUtx668mOEqy4iHoVDwZu4gNyiobPsyDzKa
        dxtSkDc8OHNV6RtzKpJOtQKBgFoRGcwbnLH5KYqX7eDDPRnj15pMU2LJx2DJVeU8
        ERY1kl7Dke6vWNzbg6WYzPoJ/unrJhFXNyFmXj213QsSvN3FyD1pFvp/R28mB/7d
        hVa93vzImdb3wxe7d7n5NYBAag9+IP8sIJ/bl6i9619uTxwvgtUqqzKPuOGY9dnh
        oce1AoGBAKZyZc/NVgqV2KgAnnYlcwNn7sRSkM8dcq0/gBMNuSZkfZSuEd4wwUzR
        iFlYp23O2nHWggTkzimuBPtD7Kq4jBey3ZkyGye+sAdmnKkOjNILNbpIZlT6gK3z
        fBaFmJGRJinKA+BJeH79WFpYN6SBZ/c3s5BusAbEU7kE5eInyazP
        -----END RSA PRIVATE KEY-----
    - kid: "iv1aShae"
      key: |
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIE8yeUh111Npqu2e5wXxjC/GA5lbGe0j0KVXqZP12vqioAcGBSuBBAAK
        oUQDQgAESKfUtKaLqCfhK+p3z870W59yOYvd+kjGWe+tK16SmWzZJbRCgdHakHE5
        MC6tJRnvedsYoKTrYoDv/XZIBI9zlA==
        -----END EC PRIVATE KEY-----
```

### `secrets.keys`

The service can use a number of key types for signing.
The following key types are supported:

- RSA
- ECDSA with the P-256 (`prime256v1`) curve
- ECDSA with the P-384 (`secp384r1`) curve
- ECDSA with the K-256 (`secp256k1`) curve

Each entry must have a unique (and arbitrary) `kid`, plus the key itself.
The key can either be specified inline (with the `key` property), or loaded from a file (with the `key_file` property).
The following key formats are supported:

- PKCS#1 PEM or DER-encoded RSA private key
- PKCS#8 PEM or DER-encoded RSA or ECDSA private key, encrypted or not
- SEC1 PEM or DER-encoded ECDSA private key

For PKCS#8 encoded keys, the `password` or `password_file` properties can be used to decrypt the key.

## `passwords`

Settings related to the local password database

```yaml
passwords:
  # Whether to enable the password database.
  # If disabled, users will only be able to log in using upstream OIDC providers
  enabled: true

  # Minimum complexity required for passwords, estimated by the zxcvbn algorithm
  # Must be between 0 and 4, default is 3
  # See https://github.com/dropbox/zxcvbn#usage for more information
  minimum_complexity: 3

  # List of password hashing schemes being used
  # /!\ Only change this if you know what you're doing
  # TODO: document this section better
  schemes:
    - version: 1
      algorithm: argon2id
```

## `account`

Configuration related to account management

```yaml
account:
  # Whether users are allowed to change their email addresses.
  #
  # Defaults to `true`.
  email_change_allowed: true

  # Whether users are allowed to change their display names
  #
  # Defaults to `true`.
  # This should be in sync with the policy in the homeserver configuration.
  displayname_change_allowed: true

  # Whether to enable self-service password registration
  #
  # Defaults to `false`.
  # This has no effect if password login is disabled.
  password_registration_enabled: false

  # Whether users are allowed to change their passwords
  #
  # Defaults to `true`.
  # This has no effect if password login is disabled.
  password_change_allowed: true

  # Whether email-based password recovery is enabled
  #
  # Defaults to `false`.
  # This has no effect if password login is disabled.
  password_recovery_enabled: false

  # Whether users are allowed to delete their own account
  #
  # Defaults to `true`.
  account_deactivation_allowed: true

  # Whether users can log in with their email address.
  #
  # Defaults to `false`.
  # This has no effect if password login is disabled.
  login_with_email_allowed: false

  # Whether registration tokens are required for password registrations.
  #
  # Defaults to `false`.
  #
  # When enabled, users must provide a valid registration token during password
  # registration. This has no effect if password registration is disabled.
  registration_token_required: false
```

## `captcha`

Settings related to CAPTCHA protection

```yaml
captcha:
    # Which service to use for CAPTCHA protection. Set to `null` (or `~`) to disable CAPTCHA protection
    service: ~

    # Use Google reCAPTCHA v2
    #service: recaptcha_v2
    #site_key: "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
    #secret_key: "6LeIxAcTAAAAAGG"-vFI1TnRWxMZNFuojJ4WifJWe

    # Use Cloudflare Turnstile
    #service: cloudflare_turnstile
    #site_key: "1x00000000000000000000AA"
    #secret_key: "1x0000000000000000000000000000000AA"

    # Use hCaptcha
    #service: hcaptcha
    #site_key: "10000000-ffff-ffff-ffff-000000000001"
    #secret_key: "0x0000000000000000000000000000000000000000"
```


## `policy`

Policy settings

```yaml
policy:
  # Path to the WASM module
  # Default in Docker distribution: `/usr/local/share/mas-cli/policy.wasm`
  # Default in pre-built binaries: `./share/policy.wasm`
  # Default in locally-built binaries: `./policies/policy.wasm`
  wasm_module: ./policies/policy.wasm
  # Entrypoint to use when evaluating client registrations
  client_registration_entrypoint: client_registration/violation
  # Entrypoint to use when evaluating user registrations
  register_entrypoint: register/violation
  # Entrypoint to use when evaluating authorization grants
  authorization_grant_entrypoint: authorization_grant/violation
  # Entrypoint to use when changing password
  password_entrypoint: password/violation
  # Entrypoint to use when adding an email address
  email_entrypoint: email/violation

  # This data is being passed to the policy
  data:
    # Users which are allowed to ask for admin access. If possible, use the
    # can_request_admin flag on users instead.
    admin_users:
      - person1
      - person2

    # Client IDs which are allowed to ask for admin access with a
    # client_credentials grant
    admin_clients:
      - 01H8PKNWKKRPCBW4YGH1RWV279
      - 01HWQCPA5KF10FNCETY9402WGF

    # Dynamic Client Registration
    client_registration:
      # don't require URIs to be on the same host. default: false
      allow_host_mismatch: false
      # allow non-SSL and localhost URIs. default: false
      allow_insecure_uris: false
      # don't require clients to provide a client_uri. default: false
      allow_missing_client_uri: false

    # Restrictions on user registration
    registration:
      # If specified, the username (localpart) *must* match one of the allowed
      # usernames. If unspecified, all usernames are allowed.
      allowed_usernames:
        # Exact usernames that are allowed
        literals: ["alice", "bob"]
        # Substrings that match allowed usernames
        substrings: ["user"]
        # Regular expressions that match allowed usernames
        regexes: ["^[a-z]+$"]
        # Prefixes that match allowed usernames
        prefixes: ["user-"]
        # Suffixes that match allowed usernames
        suffixes: ["-corp"]
      # If specified, the username (localpart) *must not* match one of the
      # banned usernames. If unspecified, all usernames are allowed.
      banned_usernames:
        # Exact usernames that are banned
        literals: ["admin", "root"]
        # Substrings that match banned usernames
        substrings: ["admin", "root"]
        # Regular expressions that match banned usernames
        regexes: ["^admin$", "^root$"]
        # Prefixes that match banned usernames
        prefixes: ["admin-", "root-"]
        # Suffixes that match banned usernames
        suffixes: ["-admin", "-root"]

    # Restrict what email addresses can be added to a user
    emails:
      # If specified, the email address *must* match one of the allowed addresses.
      # If unspecified, all email addresses are allowed.
      allowed_addresses:
        # Exact emails that are allowed
        literals: ["alice@example.com", "bob@example.com"]
        # Regular expressions that match allowed emails
        regexes: ["@example\\.com$"]
        # Suffixes that match allowed emails
        suffixes: ["@example.com"]

      # If specified, the email address *must not* match one of the banned addresses.
      # If unspecified, all email addresses are allowed.
      banned_addresses:
        # Exact emails that are banned
        literals: ["alice@evil.corp", "bob@evil.corp"]
        # Emails that contains those substrings are banned
        substrings: ["evil"]
        # Regular expressions that match banned emails
        regexes: ["@evil\\.corp$"]
        # Suffixes that match banned emails
        suffixes: ["@evil.corp"]
        # Prefixes that match banned emails
        prefixes: ["alice@"]

    requester:
      # List of IP addresses and CIDRs that are not allowed to register
      banned_ips:
        - 192.168.0.1
        - 192.168.1.0/24
        - fe80::/64

      # User agent patterns that are not allowed to register
      banned_user_agents:
        literals: ["Pretend this is Real;"]
        substrings: ["Chrome"]
        regexes: ["Chrome 1.*;"]
        prefixes: ["Mozilla/"]
        suffixes: ["Safari/605.1.15"]
```

## `rate_limiting`

Settings for limiting the rate of user actions to prevent abuse.

Each rate limiter consists of two options:
- `burst`: a base amount of how many actions are allowed in one go.
- `per_second`: how many units of the allowance replenish per second.

```yaml
rate_limiting:
  # Limits how many account recovery attempts are allowed.
  # These limits can protect against e-mail spam.
  #
  # Note: these limit also apply to recovery e-mail re-sends.
  account_recovery:
    # Controls how many account recovery attempts are permitted
    # based on source IP address.
    per_ip:
      burst: 3
      per_second: 0.0008

    # Controls how many account recovery attempts are permitted
    # based on the e-mail address that is being used for recovery.
    per_address:
      burst: 3
      per_second: 0.0002

  # Limits how many login attempts are allowed.
  #
  # Note: these limit also applies to password checks when a user attempts to
  # change their own password.
  login:
    # Controls how many login attempts are permitted
    # based on source IP address.
    # This can protect against brute force login attempts.
    per_ip:
      burst: 3
      per_second: 0.05

    # Controls how many login attempts are permitted
    # based on the account that is being attempted to be logged into.
    # This can protect against a distributed brute force attack
    # but should be set high enough to prevent someone's account being
    # casually locked out.
    per_account:
      burst: 1800
      per_second: 0.5

  # Limits how many registrations attempts are allowed,
  # based on source IP address.
  # This limit can protect against e-mail spam and against people registering too many accounts.
  registration:
    burst: 3
    per_second: 0.0008
```

## `telemetry`

Settings related to metrics and traces

```yaml
telemetry:
  tracing:
    # List of propagators to use for extracting and injecting trace contexts
    propagators:
      # Propagate according to the W3C Trace Context specification
      - tracecontext
      # Propagate according to the W3C Baggage specification
      - baggage
      # Propagate trace context with Jaeger compatible headers
      - jaeger

    # The default: don't export traces
    exporter: none

    # Export traces to an OTLP-compatible endpoint
    #exporter: otlp
    #endpoint: https://localhost:4318

  metrics:
    # The default: don't export metrics
    exporter: none

    # Export metrics to an OTLP-compatible endpoint
    #exporter: otlp
    #endpoint: https://localhost:4317

    # Export metrics by exposing a Prometheus endpoint
    # This requires mounting the `prometheus` resource to an HTTP listener
    #exporter: prometheus

  sentry:
    # DSN to use for sending errors and crashes to Sentry
    dsn: https://public@host:port/1
```

## `email`

Settings related to sending emails

```yaml
email:
  from: '"The almighty auth service" <auth@example.com>'
  reply_to: '"No reply" <no-reply@example.com>'

  # Default transport: don't send any emails
  transport: blackhole

  # Send emails using SMTP
  #transport: smtp
  #mode: plain | tls | starttls
  #hostname: localhost
  #port: 587
  #username: username
  #password: password

  # Send emails by calling a local sendmail binary
  #transport: sendmail
  #command: /usr/sbin/sendmail
```

## `upstream_oauth2`

Settings related to upstream OAuth 2.0/OIDC providers.
Additions and modifications within this section are synced with the database on server startup.
Removed entries are only removed with the [`config sync --prune`](./cli/config.md#config-sync---prune---dry-run) command.

### `upstream_oauth2.providers`

A list of upstream OAuth 2.0/OIDC providers to use to authenticate users.

Sample configurations for popular providers can be found in the [upstream provider setup](../setup/sso.md#sample-configurations) guide.

```yaml
upstream_oauth2:
  providers:
    - # A unique identifier for the provider
      # Must be a valid ULID
      id: 01HFVBY12TMNTYTBV8W921M5FA

      # The issuer URL, which will be used to discover the provider's configuration.
      # If discovery is enabled, this *must* exactly match the `issuer` field
      # advertised in `<issuer>/.well-known/openid-configuration`.
      # It must be set if OIDC discovery is enabled (which is the default).
      #issuer: https://example.com/

      # A human-readable name for the provider,
      # which will be displayed on the login page
      #human_name: Example

      # A brand identifier for the provider, which will be used to display a logo
      # on the login page. Values supported by the default template are:
      #  - `apple`
      #  - `google`
      #  - `facebook`
      #  - `github`
      #  - `gitlab`
      #  - `twitter`
      #brand_name: google

      # The client ID to use to authenticate to the provider
      client_id: mas-fb3f0c09c4c23de4

      # The client secret to use to authenticate to the provider
      # This is only used by the `client_secret_post`, `client_secret_basic`
      # and `client_secret_jwk` authentication methods
      #client_secret: f4f6bb68a0269264877e9cb23b1856ab

      # Which authentication method to use to authenticate to the provider
      # Supported methods are:
      #   - `none`
      #   - `client_secret_basic`
      #   - `client_secret_post`
      #   - `client_secret_jwt`
      #   - `private_key_jwt` (using the keys defined in the `secrets.keys` section)
      #   - `sign_in_with_apple` (a special authentication method for Sign-in with Apple)
      token_endpoint_auth_method: client_secret_post

      # Additional paramaters for the `sign_in_with_apple` authentication method
      # See https://www.oauth.com/oauth2-servers/pkce/authorization-code-flow-with-pkce/
      #sign_in_with_apple:
      #  private_key: |
      #    -----BEGIN PRIVATE KEY-----
      #    ...
      #    -----END PRIVATE KEY-----
      #  team_id: "<team-id>"
      #  key_id: "<key-id>"

      # Which signing algorithm to use to sign the authentication request when using
      # the `private_key_jwt` or the `client_secret_jwt` authentication methods
      #token_endpoint_auth_signing_alg: RS256

      # The scopes to request from the provider
      # In most cases, it should always include `openid` scope
      scope: "openid email profile"

      # How the provider configuration and endpoints should be discovered
      # Possible values are:
      #  - `oidc`: discover the provider through OIDC discovery,
      #     with strict metadata validation (default)
      #  - `insecure`: discover through OIDC discovery, but skip metadata validation
      #  - `disabled`: don't discover the provider and use the endpoints below
      #discovery_mode: oidc

      # Whether PKCE should be used during the authorization code flow.
      # Possible values are:
      #  - `auto`: use PKCE if the provider supports it (default)
      #    Determined through discovery, and disabled if discovery is disabled
      #  - `always`: always use PKCE (with the S256 method)
      #  - `never`: never use PKCE
      #pkce_method: auto

      # Whether to fetch user claims from the userinfo endpoint
      # This is disabled by default, as most providers will return the necessary
      # claims in the `id_token`
      #fetch_userinfo: true

      # If set, ask for a signed response on the userinfo endpoint, and validate
      # the response uses the given algorithm
      #userinfo_endpoint_auth_signing_alg: RS256

      # The userinfo endpoint
      # This takes precedence over the discovery mechanism
      #userinfo_endpoint: https://example.com/oauth2/userinfo

      # The provider authorization endpoint
      # This takes precedence over the discovery mechanism
      #authorization_endpoint: https://example.com/oauth2/authorize

      # The provider token endpoint
      # This takes precedence over the discovery mechanism
      #token_endpoint: https://example.com/oauth2/token

      # The provider JWKS URI
      # This takes precedence over the discovery mechanism
      #jwks_uri: https://example.com/oauth2/keys

      # The response mode we ask the provider to use for the callback
      # Possible values are:
      #  - `query`: The provider will send the response as a query string in the
      # URL search parameters. This is the default.
      #  - `form_post`: The provider will send the response as a POST request with
      # the response parameters in the request body
      #response_mode: query

      # Additional parameters to include in the authorization request
      #additional_authorization_parameters:
      #  foo: "bar"

      # Whether the `login_hint` should be forwarded to the provider in the
      # authorization request.
      #forward_login_hint: false

      # How user attributes should be mapped
      #
      # Most of those attributes have two main properties:
      #   - `action`: what to do with the attribute. Possible values are:
      #      - `ignore`: ignore the attribute
      #      - `suggest`: suggest the attribute to the user, but let them opt out
      #      - `force`: always import the attribute, and don't fail if it's missing
      #      - `require`: always import the attribute, and fail if it's missing
      #   - `template`: a Jinja2 template used to generate the value. In this template,
      #      the `user` variable is available, which contains the user's attributes
      #      retrieved from the `id_token` given by the upstream provider and/or through
      #      the userinfo endpoint.
      #
      # Each attribute has a default template which follows the well-known OIDC claims.
      #
      claims_imports:
        # The subject is an internal identifier used to link the
        # user's provider identity to local accounts.
        # By default it uses the `sub` claim as per the OIDC spec,
        # which should fit most use cases.
        subject:
          #template: "{{ user.sub }}"

        # The localpart is the local part of the user's Matrix ID.
        # For example, on the `example.com` server, if the localpart is `alice`,
        #  the user's Matrix ID will be `@alice:example.com`.
        localpart:
          #action: force
          #template: "{{ user.preferred_username }}"

        # The display name is the user's display name.
        displayname:
          #action: suggest
          #template: "{{ user.name }}"

        # An email address to import.
        email:
          #action: suggest
          #template: "{{ user.email }}"

          # Whether the email address must be marked as verified.
          # Possible values are:
          #  - `import`: mark the email address as verified if the upstream provider
          #     has marked it as verified, using the `email_verified` claim.
          #     This is the default.
          #   - `always`: mark the email address as verified
          #   - `never`: mark the email address as not verified
          #set_email_verification: import

        # An account name, for display purposes only
        # This helps end user identify what account they are using
        account_name:
          #template: "@{{ user.preferred_username }}"
```

## `experimental`

Settings that may change or be removed in future versions.
Some of which are in this section because they don't have a stable place in the configuration yet.

```yaml
experimental:
  # Time-to-live of OAuth 2.0 access tokens in seconds. Defaults to 300, 5 minutes.
  #access_token_ttl: 300

  # Time-to-live of compatibility access tokens in seconds, when refresh tokens are supported. Defaults to 300, 5 minutes.
  #compat_token_ttl: 300

  # Experimental feature to automatically expire inactive sessions
  # Disabled by default
  #inactive_session_expiration:
     # Time after which an inactive session is automatically finished in seconds
     #ttl: 32400

     # Should compatibility sessions expire after inactivity. Defaults to true.
     #expire_compat_sessions: true

     # Should OAuth 2.0 sessions expire after inactivity. Defaults to true.
     #expire_oauth_sessions: true

     # Should user sessions expire after inactivity. Defaults to true.
     #expire_user_sessions: true
```
