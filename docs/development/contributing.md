# Contributing

This document aims to get you started with contributing to the Matrix Authentication Service!

## 1. Who can contribute to MAS?

Everyone is welcome to contribute code to [Matrix Authentication Service](https://github.com/element-hq/matrix-authentication-service), provided that they are willing to license their contributions to Element under a [Contributor License Agreement](https://cla-assistant.io/element-hq/matrix-authentication-service) (CLA). This ensures that their contribution will be made available under an OSI-approved open-source license, currently Affero General Public License v3 (AGPLv3).

Please see the [Element blog post](https://element.io/blog/synapse-now-lives-at-github-com-element-hq-synapse/) for the full rationale.

## 2. What can I contribute?

There are two main ways to contribute to MAS:

- **Code and documentation**: You can contribute code to the Matrix Authentication Service and help improve its documentation by submitting pull requests to the [GitHub repository](https://github.com/element-hq/matrix-authentication-service).
- **Translations**: You can contribute translations to the Matrix Authentication Service through [Localazy](https://localazy.com/p/matrix-authentication-service).

## 3. What do I need?

To get MAS running locally from source you will need to:

- [Install Rust and Cargo](https://www.rust-lang.org/learn/get-started). We recommend using the latest stable version of Rust.
- [Install Node.js and npm](https://nodejs.org/). We recommend using the latest LTS version of Node.js.
- [Install Open Policy Agent](https://www.openpolicyagent.org/docs#1-download-opa)

## 4. Get the source

The preferred and easiest way to contribute changes is to fork the relevant project on GitHub and then [create a pull request]( https://help.github.com/articles/using-pull-requests/) to ask us to pull your changes into our repo.

Please base your changes on the `main` branch.

```sh
git clone git@github.com:YOUR_GITHUB_USER_NAME/matrix-authentication-service.git
cd matrix-authentication-service
git checkout main
```

If you need help getting started with git, this is beyond the scope of the document, but you can find many good git tutorials on the web.

## 5. Build and run MAS

- Build the frontend
  ```sh
  cd frontend
  npm ci # Install the frontend dependencies
  npm run build # Build the frontend
  cd ..
  ```
- Build the Open Policy Agent policies
  ```sh
  cd policies
  make
  # OR, if you don't have `opa` installed and want to build through the OPA docker image
  make DOCKER=1
  cd ..
  ```
- Generate the sample config via `cargo run -- config generate > config.yaml`
- To enable registration, add the following to `config.yaml`:
  ```yaml
  account:
    password_registration_enabled: true
    # Since no emails are sent by default and we want to be able to create some users for
    # local dev, remove the email requirement.
    password_registration_email_required: false
  ```
- Run a PostgreSQL database locally
  ```sh
  docker run -p 5432:5432 -e 'POSTGRES_USER=postgres' -e 'POSTGRES_PASSWORD=postgres' -e 'POSTGRES_DATABASE=postgres' postgres
  ```
- Update the database URI in `config.yaml` to `postgresql://postgres:postgres@localhost/postgres`
- Run the server via `cargo run -- server -c config.yaml`
- Go to <http://localhost:8080/>

## 6. Update generated files and format your code

The project includes a few files that are automatically generated.
Most of them can be updated by running `sh misc/update.sh` at the root of the project.

Make sure your code adheres to our Rust and TypeScript code style by running:

 - `cargo +nightly fmt` (with the nightly toolchain installed)
 - `npm run format` in the `frontend` directory
 - `make fmt` in the `policies` directory (if changed)

When updating SQL queries in the `crates/storage-pg/` crate, you may need to update the `sqlx` introspection data. To do this, make sure to install `cargo-sqlx` (`cargo install sqlx-cli`) and:

 - Apply the latest migrations: `cargo sqlx migrate run` from the `crates/storage-pg/` directory.
 - Update the `sqlx` introspection data: `cargo sqlx prepare` from the `crates/storage-pg/` directory.

## 7. Test, test, test!

While you're developing and before submitting a patch, you'll want to test your code and adhere to many code style and linting guidelines.

### Run the linters

- Run `cargo clippy --workspace` to lint the Rust code.
- Run `npm run lint` in the `frontend` directory to lint the frontend code.
- Run `make fmt` and `make lint` in the `policies` directory to format and lint the included policy.

### Run the tests

If you haven't already, install [Cargo-Nextest](https://nexte.st/docs/installation/pre-built-binaries/).

- Run the tests to the backend by running `cargo nextest run --workspace`. This requires a connection to a PostgreSQL database, set via the `DATABASE_URL` environment variable.
- Run the tests to the frontend by running `npm run test` in the `frontend` directory.
- To run the tests for the included policy, change to the `policies` directory and run one of:
  - `make test` (needs Open Policy Agent installed)
  - `make PODMAN=1 test` (runs inside a container; needs Podman installed)
  - `make DOCKER=1 test` (runs inside a container; needs Docker installed)


### Manually testing login flows

To get a better understanding of how MAS works and how things behave, you may want to
test the login flows manually.

To register a user to test with, you can use `cargo run -- manage register-user` or if
you enabled registration as described above, you can simply visit http://localhost:8080/
and create an account.

#### Test OAuth 2.0 grants

This section is all standard OAuth 2.0/OIDC flows but to jump in and test things
immediately, here's a quick walkthrough.

See the docs on [*OAuth 2.0 sessions*](../topics/authorization.md#oauth-20-sessions)
for more info.

##### Test OAuth authorization code grant (interactive)

 1. Update your MAS `config.yaml` with a [client](../reference/configuration.md#clients):
    ```
    clients:
      - client_id: 00000000000000000000SEC0ND
        client_name: "my-test-client"
        client_auth_method: none
        redirect_uris:
          - http://test-login/
    ```
 1. Visit http://localhost:8080/authorize?client_id=00000000000000000000SEC0ND&response_type=code&redirect_uri=http://test-login/&scope=openid%20email&state=xyz123
 1. Press **Continue** (or login and continue)
 1. You will be redirected back to a URL like `http://test-login/?state=xyz123&code=XXX`.
 1. Take the `code` value and exchange it for a token:
    ```http
    POST http://localhost:8080/oauth2/token
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=<code>&redirect_uri=http://test-login/&client_id=00000000000000000000SEC0ND
    ```

See the docs on [*authorization code
grant*](../topics/authorization.md#authorization-code-grant) for more info.

##### Test OAuth device authorization grant (interactive)

TODO

See the docs on [*device code
grant*](../topics/authorization.md#device-authorization-grant) for more info.

##### Test OAuth client credentials grant (non-interactive)

TODO

See the docs on [*client credentials
grant*](../topics/authorization.md#client-credentials-grant) for more info.


#### Compatibility login flows

This section is a bit of a [rehash of the Matrix spec around
logins](https://spec.matrix.org/v1.18/client-server-api/#legacy-login) but to jump in
and test things immediately, here's a quick walkthrough.

For clients that don’t support OAuth 2.0 yet, MAS has a compatibility layer to provide
the same Matrix API's that a homeserver traditionally provided. See the docs on
[*Compatibility sessions*](../topics/authorization.md#compatibility-sessions) for more
info.

You can check the list of available login flows by calling the
`/_matrix/client/v3/login` compatibility endpoint exposed by MAS:

`GET http://localhost:8080/_matrix/client/v3/login`
```json
{
  "flows": [
    {
      "type": "m.login.password"
    },
    {
      "type": "m.login.sso"
    },
    {
      "type": "m.login.token"
    }
  ]
}
```

We will go through each of these flows in the next sections.

##### Test compatibility password login (non-interactive)

This is the simplest login flow to test. Just send a normal [Matrix login
request](https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3login):

`POST http://localhost:8080/_matrix/client/v3/login`
```json
{
  "identifier": {
    "type": "m.id.user",
    "user": "cheeky_monkey"
  },
  "initial_device_display_name": "Jungle Phone",
  "password": "ilovebananas",
  "type": "m.login.password"
}
```

##### Test compatibility SSO login (interactive)

To test the SSO login flow, it's the same process as described in the [Matrix
spec](https://spec.matrix.org/v1.18/client-server-api/#client-login-via-sso).

 1. Visit http://localhost:8080/_matrix/client/v3/login/sso/redirect?redirectUrl=http://test-login/
 1. You will be redirected back to a URL like `http://test-login/?loginToken=XXX`.
 1. Take the `loginToken` value and use the compatibility token login flow (must be done
    within [30
    seconds](https://github.com/element-hq/matrix-authentication-service/blob/64f90e01da2de8e5a69e41f9031ab9ccf7457b85/crates/handlers/src/compat/login.rs#L523-L525)
    of the previous step): `POST http://localhost:8080/_matrix/client/v3/login`
    ```json
    {
      "type": "m.login.token",
      "token": "<loginToken value>"
    }
    ```


### Debug policies

When in doubt, rebuild the policies (see the *Build and run MAS* section above). It's
really easy to make a change to the policies and forget to rebuild them, which can lead
to maddening debugging sessions.

The policies get a combination of `data` and `input` when they're evaluated.

 - `data`: App-global data. This is a combination of many things:
    - Static fields defined in `mas_policy::Data`
    - `mas_policy::DynamicData` is mixed in and is managed with the admin API.
    - Arbitrary data can be added via configuration (`policy.data`) ([docs](../reference/configuration.md#policy))
 - `input`: Information passed during evaluation that is derived from each request.
    - Each policy has its own input schema defined by the types like `CompatLoginInput`, etc.

To debug what the policy template sees, you can add a
[`print(...)`](https://www.openpolicyagent.org/docs/cheatsheet#print) statement in the
policy, which will print to the [server
logs](https://github.com/matrix-org/rust-opa-wasm/blob/17cdd1570448da02f9d37bbe4e89ffad2ffc5e3f/src/policy.rs#L276)
(FIXME: this currently doesn't work).

Since the way `data` is assembled is a bit complex, you can use
`RUST_LOG=info,mas_policy=debug` which will show the `tracing::debug!("Instantiating
policy with data={}", data);` debug logs.

For `input`, you can just log it more directly where you evaluate the policy.


## 8. Submit a pull request

Once you've made changes, you're ready to submit a pull request.

When the pull request is opened, you will see a few things:

 1. Our automated CI (Continuous Integration) pipeline will run (again) the linters, the unit tests, the integration tests, and more.
 1. One or more of the developers will take a look at your pull request and offer feedback.

From this point, you should:

 1. Look at the results of the CI pipeline.
    - If there is any error, fix the error.
 1. If a developer has requested changes, make these changes and let us know when it is ready for a developer to review again.
    - A pull request is a conversation; if you disagree with the suggestions, please respond and discuss it.
 1. Create a new commit with the changes.
    - Please do *not* overwrite the history. New commits make the reviewer's life easier.
    - Push these commits to your pull request.
 1. Back to 1.
 1. Once the pull request is ready for review again, please **re-request review** from whichever developer did your initial review (or leave a comment in the pull request that you believe all required changes have been made).

Once both the CI and the developers are happy, the patch will be merged into Matrix Authentication Service and released shortly!
