# Grafana dashboard

This directory contains a Grafana dashboard for monitoring matrix-authentication-service.

It is defined using [jsonnet] and the [grafonnet] library.

## Usage

The built dashboard is available at `dashboard.json`.
Import it into Grafana to start using it.

## Development and customization

Requirements:

- [go-jsonnet]
- [jsonnet-bundler]

First install the dependencies using [jsonnet-bundler]:

```sh
jb install
```

Regenerate the dashboard using [go-jsonnet]:

```sh
jsonnet -J vendor -o dashboard.json dashboard.libsonnet
```

[jsonnet]: https://jsonnet.org/
[go-jsonnet]: https://github.com/google/go-jsonnet
[grafonnet]: https://github.com/grafana/grafonnet
[jsonnet-bundler]: https://github.com/jsonnet-bundler/jsonnet-bundler
