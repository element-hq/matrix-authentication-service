# Tchap customizations

All customization in the upstream codebase are to be surrounded with `:tchap:` tag

## Server side logic

Tchap customization in the Rust server codebase are located in the [tchap crate](../crates/tchap).

## Building templates with Tchap customization

[Tchap customizations](resources/templates) override some of the default templates.

MAS templates relies on static resources from the frontend app (mainly css), therefore some Tchap resources have been added there via the default manifest.json

The manifest.json is extended for Tchap in the vite config [vite.tchap.config.ts](../frontend/tchap/vite.tchap.config.ts)


## Customizations in the frontend app

Tchap custom React components are located in a [subdirectory](../frontend/tchap) of the frontend app.

## Custom pipeline

For building the Docker image, the [`build` github action](../.github/workflows/build.yaml) packages all MAS resources enhanced with Tchap customizations.

## Web dev

- start your docker engine, on Macos Docker Desktop

- [install rust](https://www.rust-lang.org/tools/install) : curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

- on MacOs install `brew install fswatch`

- run `start-local-mas-hot-reload.sh`

- edit templates in `./tchap/resources/templates`

If Synapse integration is needed, install the environment from element-docker-demo and run it (see README.md)

Copy synapse secret from `element-docker-demo/data/mas/config.yaml` to .env file : HOMESERVER_SECRET=


# Important knowledge

Serve directory is defined in the config.yaml, by default it is `path: "./frontend/dist/"`

```
http:
  listeners:
    - name: web
      resources:
        - name: assets
          path: "/resources/manifest.json"

```

See in the logs 

```
2025-06-03T12:28:33.967776Z  INFO mas_cli::commands::server:297 Listening on http://[::]:8080 with resources [Discovery, Human, OAuth, Compat, GraphQL { playground: false, undocumented_oauth2_access: false }, Assets { path: "./frontend/dist/" }, AdminApi] 

```