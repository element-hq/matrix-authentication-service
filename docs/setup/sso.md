# Configure an upstream SSO provider

The authentication service supports using an upstream OpenID Connect provider to authenticate its users.
Multiple providers can be configured, and can be used in conjunction with the local password database authentication.

Any OIDC compliant provider should work with the service as long as it supports the authorization code flow.

**Note that the service does not support other SSO protocols such as SAML**, and there is no plan to support them in the future.
A deployment which requires SAML or LDAP-based authentication should use a service like [Dex](https://github.com/dexidp/dex) to bridge between the SAML provider and the authentication service.

## General configuration

Configuration of upstream providers is done in the `upstream_oauth2` section of the configuration file, which has a `providers` list.
Additions and changes to this sections are synced with the database on startup.
Removals need to be applied using the [`mas-cli config sync --prune`](../reference/cli/config.md#config-sync---prune---dry-run) command.

**An exhaustive list of all the parameters is available in the [configuration file reference](../reference/configuration.md#upstream_oauth2).**

The general configuration usually goes as follows:

 - determine a unique `id` for the provider, which will be used as stable identifier between the configuration file and the database. This `id` must be a ULID, and can be generated using online tools like <https://www.ulidtools.com>
 - create an OAuth 2.0/OIDC client on the provider's side, using the following parameters:
   - `redirect_uri`: `https://<auth-service-domain>/upstream/callback/<id>`
   - `response_type`: `code`
   - `response_mode`: `query`
   - `grant_type`: `authorization_code`
 - fill the `upstream_oauth2` section of the configuration file with the following parameters:
   - `providers`:
     - `id`: the previously generated ULID
     - `client_id`: the client ID of the OAuth 2.0/OIDC client given by the provider
     - `client_secret`: the client secret of the OAuth 2.0/OIDC client given by the provider
     - `issuer`: the issuer URL of the provider
     - `scope`: the scope to request from the provider. `openid` is usually required, and `profile` and `email` are recommended to import a few user attributes.
 - setup user attributes mapping to automatically fill the user profile with data from the provider. See the [user attributes mapping](#user-attributes-mapping) section for more details.

## User attributes mapping

The authentication service supports importing the following user attributes from the provider:

 - The localpart/username (e.g. `@localpart:example.com`)
 - The display name
 - An email address
 - An account name, to help end users identify what account they are using

For each of those attributes, administrators can configure a mapping using the claims provided by the upstream provider.
They can also configure what should be done for each of those attributes. It can either:

 - `ignore`: ignore the attribute, and let the user fill it manually
 - `suggest`: suggest the attribute to the user, but let them opt-out of importing it
 - `force`: automatically import the attribute, but don't fail if it is not provided by the provider
 - `require`: automatically import the attribute, and fail if it is not provided by the provider

A Jinja2 template is used as mapping for each attribute.
The following default templates are used:

 - `localpart`: `{{ user.preferred_username }}`
 - `displayname`: `{{ user.name }}`
 - `email`: `{{ user.email }}`
 - `account_name`: none

The template has the following variables available:

 - `id_token_claims`: an object with the claims got through the `id_token` given by the provider, if provided by the provider
 - `userinfo_claims`: an object with the claims got through the `userinfo` endpoint, if `fetch_userinfo` is enabled
 - `user`: an object which contains the claims from both the `id_token` and the `userinfo` endpoint
 - `extra_callback_parameters`: an object with the additional parameters the provider sent to the redirect URL

## Multiple providers behaviour

Multiple authentication methods can be configured at the same time, in which case the authentication service will let the user choose which one to use.
This is true if both the local password database and an upstream provider are configured, or if multiple upstream providers are configured.
In such cases, the `human_name` parameter of the provider configuration is used to display a human-readable name for the provider, and the `brand_name` parameter is used to show a logo for well-known providers.

If there is only one upstream provider configured and the local password database is disabled ([`passwords.enabled`](../reference/configuration.md#passwords) is set to `false`), the authentication service will automatically trigger an authorization flow with this provider.

## Sample configurations

This section contains sample configurations for popular OIDC providers.

### Apple

Sign-in with Apple uses special non-standard for authenticating clients, which requires a special configuration.

```yaml
upstream_oauth2:
  providers:
    - id: 01JAYS74TCG3BTWKADN5Q4518C
      issuer: "https://appleid.apple.com"
      authorization_endpoint: "https://appleid.apple.com/auth/authorize"
      token_endpoint: "https://appleid.apple.com/auth/token"
      human_name: "Apple"
      client_id: "<Service ID>" # TO BE FILLED
      scope: "openid name email"
      response_mode: "form_post"
      token_endpoint_auth_method: "sign_in_with_apple"
      sign_in_with_apple:
        private_key_file: "<Location of the PEM-encoded private key file>" # TO BE FILLED
        team_id: "<Team ID>" # TO BE FILLED
        key_id: "<Key ID>" # TO BE FILLED
      claims_imports:
        localpart:
          action: ignore
        displayname:
          action: suggest
          # SiWA passes down the user infos as query parameters in the callback
          # which is available in the extra_callback_parameters variable
          template: |
            {%- set u = extra_callback_parameters["user"] | from_json -%}
            {{- u.name.firstName }} {{ u.name.lastName -}}
        email:
          action: suggest
        account_name:
          template: |
            {%- set u = extra_callback_parameters["user"] | from_json -%}
            {{- u.name.firstName }} {{ u.name.lastName -}}
```

### Authelia

These instructions assume that you have already enabled the OIDC provider support in [Authelia](https://www.authelia.com/).

Add a client for MAS to Authelia's `configuration.yaml` (see the [Authelia OIDC documentation](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/) for full details):

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: "<client-id>" # TO BE FILLED
          client_name: Matrix
          client_secret: "<client-secret>" # TO BE FILLED
          public: false
          redirect_uris:
            - https://<mas-fqdn>/upstream/callback/<id>
          scopes:
            - openid
            - groups
            - profile
            - email
          grant_types:
            - 'refresh_token'
            - 'authorization_code'
          response_types:
            - code
```

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
  - id: <id>
    human_name: Authelia
    issuer: "https://<authelia-fqdn>" # TO BE FILLED W/O ANY TRAILING SLASHES
    client_id: "<client-id>" # TO BE FILLED
    client_secret: "<client-secret>" # TO BE FILLED
    token_endpoint_auth_method: client_secret_basic
    scope: "openid profile email"
    discovery_mode: insecure
    claims_imports:
        localpart:
          action: require
          template: "{{ user.preferred_username }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```


### Authentik

[Authentik](https://goauthentik.io/) is an open-source IdP solution.

1. Create a provider in Authentik, with type OAuth2/OpenID.
2. The parameters are:
  - Client Type: Confidential
  - Redirect URIs: `https://<auth-service-domain>/upstream/callback/<id>`
3. Create an application for the authentication service in Authentik and link it to the provider.
4. Note the slug of your application, Client ID and Client Secret.

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: 01HFRQFT5QFMJFGF01P7JAV2ME
      human_name: Authentik
      issuer: "https://<authentik-domain>/application/o/<app-slug>/" # TO BE FILLED
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        localpart:
          action: require
          template: "{{ user.preferred_username }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```


### Facebook

0. You will need a Facebook developer account. You can register for one [here](https://developers.facebook.com/async/registration/).
1. On the [apps](https://developers.facebook.com/apps/) page of the developer console, "Create App", and choose "Allow people to log in with their Facebook account".
2. Once the app is created, add "Facebook Login" and choose "Web". You don't
   need to go through the whole form here.
3. In the left-hand menu, open "Use cases" > "Authentication and account creation" > "Customize" > "Settings"
   * Add `https://<auth-service-domain>/upstream/callback/<id>` as an OAuth Redirect URL.
4. In the left-hand menu, open "App settings/Basic". Here you can copy the "App ID" and "App Secret" for use below.

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01HFS3WM7KSWCEQVJTN0V9X1W6"
      issuer: "https://www.facebook.com"
      human_name: "Facebook"
      brand_name: "facebook"
      discovery_mode: disabled
      pkce_method: always
      authorization_endpoint: "https://facebook.com/v11.0/dialog/oauth/"
      token_endpoint: "https://graph.facebook.com/v11.0/oauth/access_token"
      jwks_uri: "https://www.facebook.com/.well-known/oauth/openid/jwks/"
      token_endpoint_auth_method: "client_secret_post"
      client_id: "<app-id>" # TO BE FILLED
      client_secret: "<app-secret>" # TO BE FILLED
      scope: "openid"
      claims_imports:
        localpart:
          action: ignore
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
        account_name:
          template: "{{ user.name }}"
```


### GitLab

1. Create a [new application](https://gitlab.com/profile/applications).
2. Add the `openid` scope. Optionally add the `profile` and `email` scope if you want to import the user's name and email.
3. Add this Callback URL: `https://<auth-service-domain>/upstream/callback/<id>`

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01HFS67GJ145HCM9ZASYS9DC3J"
      issuer: "https://gitlab.com"
      human_name: "GitLab"
      brand_name: "gitlab"
      token_endpoint_auth_method: "client_secret_post"
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        displayname:
          action: suggest
          template: "{{ user.name }}"
        localpart:
          action: ignore
        email:
          action: suggest
          template: "{{ user.email }}"
        account_name:
          template: "@{{ user.preferred_username }}"
```

### GitHub

GitHub doesn't support OpenID Connect, but it does support OAuth 2.0.
It will use the `fetch_userinfo` option with a manual `userinfo_endpoint` to fetch the user's profile through the GitHub API.

1. Create a [new application](https://github.com/settings/applications/new).
2. Fill in the form with an application name and homepage URL.
3. Use the following Authorization callback URL: `https://<auth-service-domain>/upstream/callback/<id>`
4. Retrieve the Client ID
5. Generate a Client Secret and copy it

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01HFS67GJ145HCM9ZASYS9DC3J"
      human_name: GitHub
      brand_name: github
      discovery_mode: disabled
      fetch_userinfo: true
      token_endpoint_auth_method: "client_secret_post"
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      authorization_endpoint: "https://github.com/login/oauth/authorize"
      token_endpoint: "https://github.com/login/oauth/access_token"
      userinfo_endpoint: "https://api.github.com/user"
      scope: "read:user"
      claims_imports:
        subject:
          template: "{{ userinfo_claims.id }}"
        displayname:
          action: suggest
          template: "{{`{{ userinfo_claims.name }}"
        localpart:
          action: ignore
        email:
          action: suggest
          template: "{{ userinfo_claims.email }}"
        account_name:
          template: "@{{ userinfo_claims.login }}"
```


### Google

1. Set up a project in the Google API Console (see [documentation](https://developers.google.com/identity/protocols/oauth2/openid-connect#appsetup))
2. Add an "OAuth Client ID" for a Web Application under ["Credentials"](https://console.developers.google.com/apis/credentials)
3. Add the following "Authorized redirect URI": `https://<auth-service-domain>/upstream/callback/<id>`

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: 01HFS6S2SVAR7Y7QYMZJ53ZAGZ
      human_name: Google
      brand_name: "google"
      issuer: "https://accounts.google.com"
      token_endpoint_auth_method: "client_secret_post"
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        localpart:
          action: ignore
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
        account_name:
          template: "{{ user.email }}"
```


### Keycloak


Follow the [Getting Started Guide](https://www.keycloak.org/guides) to install Keycloak and set up a realm.

1. Click `Clients` in the sidebar and click `Create`
2. Fill in the fields as below:

   | Field | Value |
   |-----------|-----------|
   | Client ID | `matrix-authentication-service` |
   | Client Protocol | `openid-connect` |

3. Click `Save`
4. Fill in the fields as below:

   | Field | Value |
   |-----------|-----------|
   | Client ID | `matrix-authentication-service` |
   | Enabled | `On` |
   | Client Protocol | `openid-connect` |
   | Access Type | `confidential` |
   | Valid Redirect URIs | `https://<auth-service-domain>/upstream/callback/<id>` |

5. Click `Save`
6. On the Credentials tab, update the fields:

   | Field | Value |
   |-------|-------|
   | Client Authenticator | `Client ID and Secret` |

7. Click `Regenerate Secret`
8. Copy Secret

```yaml
upstream_oauth2:
  providers:
    - id: "01H8PKNWKKRPCBW4YGH1RWV279"
      issuer: "https://<keycloak>/realms/<realm>" # TO BE FILLED
      token_endpoint_auth_method: client_secret_basic
      client_id: "matrix-authentication-service"
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        localpart:
          action: require
          template: "{{ user.preferred_username }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
```


### Microsoft Azure Active Directory

Azure AD can act as an OpenID Connect Provider.
Register a new application under *App registrations* in the Azure AD management console.
The `RedirectURI` for your application should point to your authentication service instance:
`https://<auth-service-domain>/upstream/callback/<id>` where `<id>` is the same as in the config file.

Go to *Certificates & secrets* and register a new client secret.
Make note of your Directory (tenant) ID as it will be used in the Azure links.

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01HFRPWGR6BG9SAGAKDTQHG2R2"
      human_name: Microsoft Azure AD
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0" # TO BE FILLED
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      discovery_mode: insecure

      claims_imports:
        localpart:
          action: require
          template: "{{ (user.preferred_username | split('@'))[0] }}"
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
          set_email_verification: always
        account_name:
          template: "{{ user.preferred_username }}"
```

### Discord

1. Create a new application in the Discord Developer Portal (see [documentation](https://discord.com/developers/applications))
2. Add the following "Redirect URI" in the OAuth2 tab under settings: `https://<auth-service-domain>/upstream/callback/<id>`

Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: 01JQK7DK6VFH62NMW4HS9RKD3R
      human_name: Discord
      brand_name: "discord"
      token_endpoint_auth_method: "client_secret_post"
      issuer: "https://discord.com"
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      fetch_userinfo: true
      userinfo_endpoint: "https://discord.com/api/users/@me"
      scope: "openid identify email"
      claims_imports:
        localpart:
          action: suggest
          template: "{{ user.username }}"
        displayname:
          action: suggest
          template: "{{ user.global_name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
        account_name:
          template: "{{ user.username }}"
```


### Rauthy

1. Click `Clients` in the Rauthy Admin sidebar and click `Add new Client`
2. Fill in the fields as below:

   | Field | Value |
   |-----------|-----------|
   | Client ID | `matrix-authentication-service` |
   | Client Name | `matrix-authentication-service` |
   | Redirect URI | `https://<auth-service-domain>/upstream/callback/<id>` |

3. Set the client to be `Confidential`.

4. Click `Save`

5. Select the client you just created from the clients list.
6. Enable the `authorization_code`, and `refresh_token` grant types.
7. Set the allowed scopes to `openid`, `profile`, and `email`.
8. Set both Access Algorithm and ID Algorithm to `RS256`.
9. Set PKCE challenge method to `S256`.
10. Click `Save`
11. Copy the `Client ID` from the `Config` tab and the `Client Secret` from the `Secret` tab.


Authentication service configuration:

```yaml
upstream_oauth2:
  providers:
    - id: "01JFFHK7HJF70YSYF753GEWVRP"
      human_name: Rauthy
      issuer: "https://<rauthy>/auth/v1" # TO BE FILLED
      client_id: "<client-id>" # TO BE FILLED
      client_secret: "<client-secret>" # TO BE FILLED
      scope: "openid profile email"
      claims_imports:
        localpart:
          action: ignore
        displayname:
          action: suggest
          template: "{{ user.given_name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
```

To use a Rauthy-supported [Ephemeral Client](https://sebadob.github.io/rauthy/work/ephemeral_clients.html#ephemeral-clients), use this JSON document:

```json
{
  "client_id": "https://path.to.this.json",
  "redirect_uris": [
    "https://your-app.com/callback"
  ],
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "access_token_signed_response_alg": "RS256",
  "id_token_signed_response_alg": "RS256"
}
```
