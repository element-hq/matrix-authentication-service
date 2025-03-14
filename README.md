# OAuth2.0 + OpenID Connect Provider for Matrix Homeservers

MAS (Matrix Authentication Service) is an OAuth 2.0 and OpenID Provider server for Matrix.

It has been created to support the migration of Matrix to an OpenID Connect (OIDC) based authentication layer as per [MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861).

See the [Documentation](https://element-hq.github.io/matrix-authentication-service/index.html) for information on installation and use.

You can learn more about Matrix and OIDC at [areweoidcyet.com](https://areweoidcyet.com/).

![Delegated OIDC architecture with MAS overview](overview.png)

## Features

- Supported homeservers
  - ✅ Synapse
- Authentication methods:
  - ✅ Upstream OIDC
  - 🚧 Local password
  - ‼️ [Application Services login](https://element-hq.github.io/matrix-authentication-service/as-login.html) (**Encrypted bridges**)
- Migration support
  - ✅ Compatibility layer for legacy Matrix authentication
  - ✅ Advisor on migration readiness
  - ✅ Import users from Synapse
  - ✅ Import password hashes from Synapse
  - ✅ Import of external subject IDs for upstream identity providers from Synapse

## Upstream Identity Providers

MAS is known to work with the following upstream IdPs via OIDC:

- [Keycloak](https://www.keycloak.org/)
- [Dex](https://dexidp.io/)
- [Google](https://developers.google.com/identity/openid-connect/openid-connect)

## Copyright & License

Copyright 2021-2025 New Vector Ltd

This software is dual-licensed by New Vector Ltd (Element). It can be used either:

(1) for free under the terms of the GNU Affero General Public License (as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version); OR

(2) under the terms of a paid-for Element Commercial License agreement between you and Element (the terms of which may vary depending on what you and Element have agreed to).
Unless required by applicable law or agreed to in writing, software distributed under the Licenses is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licenses for the specific language governing permissions and limitations under the Licenses.

