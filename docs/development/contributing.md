# Contributing

This document aims to get you started with contributing to the Matrix Authentication Service!

## 1. Who can contribute to MAS?

Everyone is welcome to contribute code to [Synapse](https://github.com/element-hq/matrix-authentication-service), provided that they are willing to license their contributions to Element under a [Contributor License Agreement](https://cla-assistant.io/element-hq/matrix-authentication-service) (CLA). This ensures that their contribution will be made available under an OSI-approved open-source license, currently Affero General Public License v3 (AGPLv3).

Please see the [Element blog post](https://element.io/blog/synapse-now-lives-at-github-com-element-hq-synapse/) for the full rationale.

## 2. What can I contribute?

There are two main ways to contribute to MAS:

- **Code and documentation**: You can contribute code to the Matrix Authentication Service and help improve its documentation by submitting pull requests to the [GitHub repository](https://github.com/element-hq/matrix-authentication-service).
- **Translations**: You can contribute translations to the Matrix Authentication Service through [Localazy](https://localazy.com/p/matrix-authentication-service).

## 3. What do I need?

To get MAS running locally from source you will need:

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

When updating SQL queries in the `crates/storage-pg/` crate, you may need to update the `sqlx` introspection data. To do this, make sure to install `cargo-sqlx` (`cargo install sqlx-cli`) and:

 - Apply the latest migrations: `cargo sqlx migrate run` from the `crates/storage-pg/` directory.
 - Update the `sqlx` introspection data: `cargo sqlx prepare` from the `crates/storage-pg/` directory.

## 7. Test, test, test!

While you're developing and before submitting a patch, you'll want to test your code and adhere to many code style and linting guidelines.

### Run the linters

- Run `cargo clippy --workspace` to lint the Rust code.
- Run `npm run lint` in the `frontend` directory to lint the frontend code.

### Run the tests

- Run the tests to the backend by running `cargo test --workspace`. This requires a connection to a PostgreSQL database, set via the `DATABASE_URL` environment variable.
- Run the tests to the frontend by running `npm run test` in the `frontend` directory.

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
