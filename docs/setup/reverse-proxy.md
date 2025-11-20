# Configuring a reverse proxy

Although the service can be exposed directly to the internet, including handling the TLS termination, many deployments will want to run a reverse proxy in front of the service.

In those configuration, the service should be configured to listen on `localhost` or Unix domain socket.

## Example configuration

```yaml
http:
  public_base: https://auth.example.com/
  listeners:
    - name: web
      resources:
        - name: discovery
        - name: human
        - name: oauth
        - name: compat
        - name: graphql
        - name: assets

      binds:
        # Bind on a local port
        - host: localhost
          port: 8080

        # OR bind on a Unix domain socket
        #- socket: /var/run/mas.sock

        # OR bind on a systemd socket
        #- fd: 0
        #  kind: tcp # or unix

      # Optional: use the PROXY protocol
      #proxy_protocol: true
```

## Base nginx configuration

A basic configuration for `nginx`, which proxies traffic to the service would look like this:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    ssl_certificate path/to/fullchain.pem;
    ssl_certificate_key path/to/privkey.pem;

    location / {
        proxy_http_version 1.1;
        proxy_pass http://localhost:8080;
        # OR via the Unix domain socket
        #proxy_pass http://unix:/var/run/mas.sock;

        # Forward the client IP address
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # or, using the PROXY protocol
        #proxy_protocol on;
    }
}
```

## Compatibility layer

For the compatibility layer, the following endpoints need to be proxied to the service:

 - `/_matrix/client/*/login`
 - `/_matrix/client/*/logout`
 - `/_matrix/client/*/refresh`

For example, a nginx configuration could look like:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name matrix.example.com;

    # Forward to the auth service
    location ~ ^/_matrix/client/(.*)/(login|logout|refresh) {
        proxy_http_version 1.1;
        proxy_pass http://localhost:8080;
        # OR via the Unix domain socket
        #proxy_pass http://unix:/var/run/mas.sock;

        # Forward the client IP address
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # or, using the PROXY protocol
        #proxy_protocol on;
    }

    # Forward to Synapse
    # as per https://element-hq.github.io/synapse/latest/reverse_proxy.html#nginx
    location ~ ^(/_matrix|/_synapse) {
        proxy_pass http://localhost:8008;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        client_max_body_size 50M;
        proxy_http_version 1.1;
    }
}
```

## Preserve the client IP

For rate-limiting and logging purposes, MAS needs to know the client IP address, which can be lost when using a reverse proxy.
There are two ways to preserve the client IP address

### `X-Forwarded-For` header

MAS can infer the client IP address from the `X-Forwarded-For` header.
It will trust the value for this header only if the request comes from a trusted reverse proxy.

The range of IPs that can be trusted is configured using the `trusted_proxies` configuration option, which has the default private IP ranges.

```yaml
http:
  trusted_proxies:
  - 192.168.0.0/16
  - 172.16.0.0/12
  - 10.0.0.0/10
  - 127.0.0.1/8
  - fd00::/8
  - ::1/128
```

With nginx, this can be achieved by setting the `proxy_set_header` directive to `X-Forwarded-For $proxy_add_x_forwarded_for`.

### Proxy protocol

MAS supports the [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) to preserve the client IP address.
To enable it, enable the `proxy_protocol` option on the listener:

```yaml
http:
  listeners:
    - name: web
      resources:
        - name: discovery
        - name: human
        - name: oauth
        - name: compat
        - name: graphql
        - name: assets
      binds:
        - address: "[::]:8080"
      proxy_protocol: true
```

With nginx, this can be achieved by setting the `proxy_protocol` directive to `on` in the `location` block.

## Serve assets directly

To avoid unnecessary round-trips, the assets can be served directly by nginx, and the `assets` resource can be removed from the service configuration.

```yaml
http:
  listeners:
    - name: web
      resources:
        - name: discovery
        - name: human
        - name: oauth
        - name: compat
        - name: graphql
        # MAS doesn't need to serve the assets anymore
        #- name: assets
      binds:
        - address: "[::]:8080"
      proxy_protocol: true
```

Make sure the assets directory served by nginx is up to date.

```nginx
server {
    # --- SNIP ---

    location / {
        # --- SNIP ---
    }

    # Make nginx serve the assets directly
    location /assets/ {
        root /path/to/share/assets/;

        # Serve pre-compressed assets
        gzip_static on;
        # With the ngx_brotli module installed
        # https://github.com/google/ngx_brotli
        #brotli_static on;

        # Cache assets for a year
        expires 365d;
    }
}
```
