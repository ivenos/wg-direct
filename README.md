# wg-direct

Minimal WireGuard image for site-to-site connections, configured only through Docker Compose environment variables.

## Why this image

- No manual private/public key generation or exchange.
- Small set of required variables.
- Deterministic key derivation from one shared secret using **HMAC-SHA256**.
- Reproducible setup across environments.

## Pull image

```sh
docker pull ghcr.io/ivenos/wg-direct:latest
```

## Quick start (Docker Compose)

### Server

```yaml
services:
  wg-server:
    image: ghcr.io/ivenos/wg-direct:latest
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
    environment:
      WG_ROLE: server
      WG_SECRET: "your-long-shared-secret"
      WG_PORT: "51820" # optional
    ports:
      - "51820:51820/udp"
    restart: unless-stopped
```

### Client

```yaml
services:
  wg-client:
    image: ghcr.io/ivenos/wg-direct:latest
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
    environment:
      WG_ROLE: client
      WG_SECRET: "your-long-shared-secret"
      WG_SERVER_ENDPOINT: "your-server.example.com:51820"
      WG_ALLOWED_IPS: "10.77.0.1/32,192.168.10.0/24" # optional
    restart: unless-stopped
```

## Variables

| Variable | Description | Default |
|---|---|---|
| `WG_ROLE` | Node role: `server` or `client` | none (required) |
| `WG_SECRET` | Shared secret; must be identical on both sides | none (required) |
| `WG_SERVER_ENDPOINT` | Server endpoint (`host:port`), client only | none (required on client) |
| `WG_PORT` | WireGuard listen port | `51820` |
| `WG_ALLOWED_IPS` | Routes sent to peer (mainly client-side) | client: `10.77.0.1/32`, server: peer tunnel IP |
| `WG_ADDRESS` | Local tunnel address | server: `10.77.0.1/30`, client: `10.77.0.2/30` |
| `WG_KEEPALIVE` | Persistent keepalive (client) | `25` |

## Generating a secure `WG_SECRET`

Use a cryptographically random 256-bit value. Only alphanumeric characters – no escaping needed in shell or YAML:

```sh
openssl rand -hex 32
```

Set the **same value** on both server and client.

## `WG_ALLOWED_IPS` examples

- `10.77.0.1/32` → route only the server tunnel IP.
- `10.77.0.1/32,192.168.10.0/24` → route tunnel IP + remote LAN.
- `0.0.0.0/0` → route all IPv4 traffic through the tunnel.

## Start

```sh
docker compose up -d
```
