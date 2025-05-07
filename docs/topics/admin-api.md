# Admin API

MAS provides a REST-like API for administrators to manage the service.
This API is intended to build tools on top of MAS, and is only available to administrators.

> **Note:** This Admin API is now the correct way for external tools to interact with MAS. External access to the [Internal GraphQL API](../development/graphql.md) is deprecated and will be removed in a future release.

## Enabling the API

The API isn't exposed by default, and must be added to either a public or a private HTTP listener.
It is considered safe to expose the API to the public, as access to it is gated by the `urn:mas:admin` scope.

To enable the API, tweak the [`http.listeners`](../reference/configuration.md#httplisteners) configuration section to add the `adminapi` resource:

```yaml
http:
  listeners:
    - name: web
      resources:
        # Other public resources
        - name: discovery
        # …
        - name: adminapi
      binds:
        - address: "[::]:8080"
    # or to a separate, internal listener:
    - name: internal
      resources:
        # Other internal resources
        - name: health
        - name: prometheus
        # …
        - name: adminapi
      binds:
        - host: localhost
          port: 8081
```

## Reference documentation

The API is documented using the [OpenAPI specification](https://spec.openapis.org/oas/v3.1.0).
The API schema is available [here](../api/spec.json).
This schema can be viewed in tools like Swagger UI, available [here](../api/).

If admin API is enabled, MAS will also serve the specification at `/api/spec.json`, with a Swagger UI available at `/api/doc/`.

## Authentication

All requests to the admin API are gated using access tokens obtained using OAuth 2.0 grants.
They must have the [`urn:mas:admin`](../reference/scopes.md#urnmasadmin) scope.

### User-interactive tools

If the intent is to build admin tools where the administrator logs in themselves, interactive grants like the [authorization code] grant or the [device authorization] grant should be used.

In this case, whether the user can request admin access or not is defined by the `can_request_admin` attribute of the user.

To try it out in Swagger UI, a client can be defined statically in the configuration file like this:

```yaml
clients:
  - client_id: 01J44Q10GR4AMTFZEEF936DTCM
    # For the authorization_code grant, Swagger UI uses the client_secret_post authentication method
    client_auth_method: client_secret_post
    client_secret: wie9oh2EekeeDeithei9Eipaeh2sohte
    redirect_uris:
      # The Swagger UI callback in the hosted documentation
      - https://element-hq.github.io/matrix-authentication-service/api/oauth2-redirect.html
      # The Swagger UI callback hosted by the service
      - https://mas.example.com/api/doc/oauth2-callback
```

Then, in Swagger UI, click on the "Authorize" button.
In the modal, enter the client ID and client secret **in the `authorizationCode` section**, select the `urn:mas:admin` scope and click on the "Authorize" button.

### Automated tools

If the intent is to build tools that are not meant to be used by humans, the client credentials grant should be used.

In this case, the client must be listed in the [`policy.data.admin_clients`](../reference/configuration.md#policy) configuration option.

```yaml
policy:
  data:
    admin_clients:
      - 01J44QC8BCY7FCFM7WGHQGKMTJ
```

To try it out in Swagger UI, a client can be defined statically in the configuration file like this:

```yaml
clients:
  - client_id: 01J44QC8BCY7FCFM7WGHQGKMTJ
    # For the client_credentials grant, Swagger UI uses the client_secret_basic authentication method
    client_auth_method: client_secret_basic
    client_secret: eequie6Oth4Ip2InahT5zuQu8OuPohLi
```

Then, in Swagger UI, click on the "Authorize" button.
In the modal, enter the client ID and client secret **in the `clientCredentials` section**, select the `urn:mas:admin` scope and click on the "Authorize" button.


## General API shape

The API takes inspiration from the [JSON API](https://jsonapi.org/) specification for its request and response shapes.

### Single resource

When querying a single resource, the response is generally shaped like this:

```json
{
  "data": {
    "type": "type-of-the-resource",
    "id": "unique-id-for-the-resource",
    "attributes": {
      "some-attribute": "some-value"
    },
    "links": {
      "self": "/api/admin/v1/type-of-the-resource/unique-id-for-the-resource"
    }
  },
  "links": {
    "self": "/api/admin/v1/type-of-the-resource/unique-id-for-the-resource"
  }
}
```

### List of resources

When querying a list of resources, the response is generally shaped like this:

```json
{
  "meta": {
    "count": 42
  },
  "data": [
    {
      "type": "type-of-the-resource",
      "id": "unique-id-for-the-resource",
      "attributes": {
        "some-attribute": "some-value"
      },
      "links": {
        "self": "/api/admin/v1/type-of-the-resource/unique-id-for-the-resource"
      }
    },
    { "...": "..." },
    { "...": "..." }
  ],
  "links": {
    "self": "/api/admin/v1/type-of-the-resource?page[first]=10&page[after]=some-id",
    "first": "/api/admin/v1/type-of-the-resource?page[first]=10",
    "last": "/api/admin/v1/type-of-the-resource?page[last]=10",
    "next": "/api/admin/v1/type-of-the-resource?page[first]=10&page[after]=some-id",
    "prev": "/api/admin/v1/type-of-the-resource?page[last]=10&page[before]=some-id"
  }
}
```

The `meta` will have the total number of items in it, and the `links` object contains the links to the next and previous pages, if any.

Pagination is cursor-based, where the ID of items is used as the cursor.
Resources can be paginated forwards using the `page[after]` and `page[first]` parameters, and backwards using the `page[before]` and `page[last]` parameters.

### Error responses

Error responses will use a 4xx or 5xx status code, with the following shape:

```json
{
  "errors": [
    {
      "title": "Error title"
    }
  ]
}
```

Well-known error codes are not yet specified.

## Example

With the following configuration:

```yaml
clients:
  - client_id: 01J44RKQYM4G3TNVANTMTDYTX6
    client_auth_method: client_secret_basic
    client_secret: phoo8ahneir3ohY2eigh4xuu6Oodaewi

policy:
  data:
    admin_clients:
      - 01J44RKQYM4G3TNVANTMTDYTX6
```

`curl` example to list the users that are not locked and have the `can_request_admin` flag set to `true`:

```bash
CLIENT_ID=01J44RKQYM4G3TNVANTMTDYTX6
CLIENT_SECRET=phoo8ahneir3ohY2eigh4xuu6Oodaewi

# Get an access token
curl \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=urn:mas:admin" \
  https://mas.example.com/oauth2/token \
  | jq -r '.access_token' \
  | read -r ACCESS_TOKEN

# List users (The -g flag prevents curl from interpreting the brackets in the URL)
curl \
  -g \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  'https://mas.example.com/api/admin/v1/users?filter[can_request_admin]=true&filter[status]=active&page[first]=100' \
  | jq
```

<details>
<summary>
Sample output
</summary>

```json
{
  "meta": {
    "count": 2
  },
  "data": [
    {
      "type": "user",
      "id": "01J2KDPHTZYW3TAT1SKVAD63SQ",
      "attributes": {
        "username": "kilgore-trout",
        "created_at": "2024-07-12T12:11:46.911578Z",
        "locked_at": null,
        "can_request_admin": true
      },
      "links": {
        "self": "/api/admin/v1/users/01J2KDPHTZYW3TAT1SKVAD63SQ"
      }
    },
    {
      "type": "user",
      "id": "01J3G5W8MRMBJ93ZYEGX2BN6NK",
      "attributes": {
        "username": "quentin",
        "created_at": "2024-07-23T16:13:04.024378Z",
        "locked_at": null,
        "can_request_admin": true
      },
      "links": {
        "self": "/api/admin/v1/users/01J3G5W8MRMBJ93ZYEGX2BN6NK"
      }
    }
  ],
  "links": {
    "self": "/api/admin/v1/users?filter[can_request_admin]=true&filter[status]=active&page[first]=100",
    "first": "/api/admin/v1/users?filter[can_request_admin]=true&filter[status]=active&page[first]=100",
    "last": "/api/admin/v1/users?filter[can_request_admin]=true&filter[status]=active&page[last]=100"
  }
}
```

</details>

[authorization code]: ../topics/authorization.md#authorization-code-grant
[device authorization]: ../topics/authorization.md#device-authorization-grant
