# Preview environment topology

How this repository deploys as an ephemeral per-PR environment. Three workloads,
no external identity provider, no persistent volumes.

| Workload | Source | Port |
| --- | --- | --- |
| `server` | this repo, `combined/Dockerfile.autonoma` | 8080 |
| `dashboard` | `Autonoma-Labs/dashboard`, `docker/Dockerfile.autonoma` | 80 |
| `db` | Postgres 16 | 5432 |

`server` is the combined NetBird server: management, signal, relay and the
embedded Dex identity provider in one process on one port. It multiplexes by
request shape (`management/internals/server/server.go` `handlerFunc`):

- HTTP/2 with a gRPC content type goes to the gRPC server,
- `/ws-proxy/management` is the WebSocket transport for the same gRPC,
- `/oauth2/*` is the embedded IdP,
- everything else is the REST API under `/api`.

Only the WebSocket and plain-HTTP paths survive an HTTP/1.1 ingress, which is
what the browser client uses, so a preview needs no HTTP/2 or gRPC support at
the edge.

## Why the two extra Dockerfiles

`combined/Dockerfile.multistage` builds from source but expects a `config.yaml`
to be mounted, and the combined server does no environment expansion of its own
(`combined/cmd/config.go` `LoadConfig` is a plain read and unmarshal). An
ephemeral environment does not know its own public hostname until it is
scheduled, and `exposedAddress`, the OIDC issuer and the dashboard redirect URIs
all derive from it. `combined/Dockerfile.autonoma` therefore keeps the same
build and swaps the entrypoint for `combined/autonoma-entrypoint.sh`, which
renders the file from the environment at start.

The dashboard's `docker/Dockerfile` only copies a pre-built `out/`, produced on
the host by `build.sh`. `docker/Dockerfile.autonoma` adds the builder stage so
the image builds straight from a checkout; its runtime stage is unchanged.

Both are additive. Nothing in the upstream build path is modified.

## Configuration

`server` reads (see `combined/autonoma-entrypoint.sh` for the full list and
defaults):

| Variable | Value |
| --- | --- |
| `NB_EXPOSED_ADDRESS` | the server's own public origin; defaults to `AUTONOMA_PREVIEWKIT_URL` |
| `NB_DASHBOARD_URL` | the dashboard's public origin, for the OAuth2 redirect URIs |
| `NB_STORE_DSN` | Postgres DSN; store, activity store and auth store all use it |
| `NB_OWNER_EMAIL` / `NB_OWNER_PASSWORD` | seeds the first owner so a throwaway environment is loggable-into without walking `/setup` |
| `NB_AUTH_SECRET` | relay shared secret; random per container when unset |

`dashboard` reads the stock runtime variables its `config.json` template names.
The ones that matter: `AUTH_AUTHORITY` is the server's origin plus `/oauth2`,
`AUTH_CLIENT_ID` and `AUTH_AUDIENCE` are both `netbird-dashboard` (the embedded
IdP's static client, `management/server/idp/embedded.go`), `USE_AUTH0` is
`false`, and `NETBIRD_MGMT_API_ENDPOINT` is the server's origin.

## Known gaps

- **No UDP.** An HTTP-only ingress cannot publish UDP/3478, so the embedded STUN
  server is disabled and clients are pointed at a public STUN server instead.
  Peers that cannot connect directly fall back to the WebSocket relay, which is
  the path the browser client takes anyway.
- **No RDP assets.** `public/ironrdp-pkg` is populated from a GitHub release in
  the dashboard's own workflow and is not fetched during the image build.
  Browser SSH works; browser RDP does not.
- **Health check.** `/oauth2/.well-known/openid-configuration` is the readiness
  path: it is unauthenticated and only returns 200 once the identity provider is
  wired up, which is the same condition as "a user can log in". The dedicated
  health server listens on a separate port and is not reachable through an
  ingress that only forwards the app port.
