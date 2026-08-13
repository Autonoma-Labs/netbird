#!/usr/bin/env bash
#
# Renders /etc/netbird/config.yaml from environment variables, then starts the
# combined NetBird server.
#
# The combined server reads its whole configuration from a YAML file and does no
# environment expansion of its own (combined/cmd/config.go LoadConfig is a plain
# ReadFile + Unmarshal). A container scheduled into an ephemeral environment does
# not know its own public hostname until it is scheduled, so the file cannot be
# baked at build time: exposedAddress, the OIDC issuer and the dashboard redirect
# URIs all depend on the hostname the environment was handed. This renders them at
# start instead.
#
# Every variable has a default, so the image also runs standalone.

set -euo pipefail

CONFIG_PATH="${NB_CONFIG_PATH:-/etc/netbird/config.yaml}"

# The public origin peers and browsers reach this server on, e.g.
# https://abc123.preview.example.com. Everything else derives from it: the relay
# address (rels://host), the signal URI, and the DNS domain.
EXPOSED_ADDRESS="${NB_EXPOSED_ADDRESS:-${AUTONOMA_PREVIEWKIT_URL:-}}"
if [[ -z "${EXPOSED_ADDRESS}" ]]; then
    echo "NB_EXPOSED_ADDRESS (or AUTONOMA_PREVIEWKIT_URL) must be set to this server's public origin" >&2
    exit 1
fi
EXPOSED_ADDRESS="${EXPOSED_ADDRESS%/}"

# Where the dashboard is served. Its origin may differ from the server's - the
# OAuth2 redirect URIs have to name the dashboard, not this server.
DASHBOARD_URL="${NB_DASHBOARD_URL:-${EXPOSED_ADDRESS}}"
DASHBOARD_URL="${DASHBOARD_URL%/}"

LISTEN_PORT="${NB_LISTEN_PORT:-${PORT:-8080}}"
DATA_DIR="${NB_DATA_DIR:-/var/lib/netbird}"
LOG_LEVEL="${NB_LOG_LEVEL:-info}"
DNS_DOMAIN="${NB_DNS_DOMAIN:-netbird.selfhosted}"

# The embedded Dex IdP is mounted at /oauth2 on this same port
# (management/internals/server/server.go handlerFunc).
AUTH_ISSUER="${NB_AUTH_ISSUER:-${EXPOSED_ADDRESS}/oauth2}"

# Shared secret the local relay authenticates with. Validate() rejects an empty
# one whenever the local relay runs.
AUTH_SECRET="${NB_AUTH_SECRET:-$(head -c 32 /dev/urandom | base64 | tr -d '\n')}"
COOKIE_KEY="${NB_IDP_SESSION_COOKIE_ENCRYPTION_KEY:-$(head -c 32 /dev/urandom | base64 | tr -d '\n')}"

# Local STUN needs UDP/3478 published, which an HTTP-only ingress cannot do, so
# point clients at a reachable STUN server instead. Setting `stuns` is also what
# disables the embedded STUN listener (config.go autoConfigureClientSettings).
STUN_URI="${NB_STUN_URI:-stun:stun.l.google.com:19302}"

STORE_ENGINE="${NB_STORE_ENGINE:-sqlite}"
STORE_DSN="${NB_STORE_DSN:-}"
if [[ -n "${STORE_DSN}" ]]; then
    STORE_ENGINE="${NB_STORE_ENGINE:-postgres}"
fi

mkdir -p "$(dirname "${CONFIG_PATH}")" "${DATA_DIR}"

{
    echo "server:"
    echo "  listenAddress: \":${LISTEN_PORT}\""
    echo "  exposedAddress: \"${EXPOSED_ADDRESS}\""
    echo "  healthcheckAddress: \"${NB_HEALTHCHECK_ADDRESS:-:9000}\""
    echo "  metricsPort: ${NB_METRICS_PORT:-9090}"
    echo "  logLevel: \"${LOG_LEVEL}\""
    echo "  logFile: \"console\""
    echo "  dataDir: \"${DATA_DIR}\""
    echo "  authSecret: \"${AUTH_SECRET}\""
    echo "  disableAnonymousMetrics: ${NB_DISABLE_ANONYMOUS_METRICS:-true}"
    echo "  disableGeoliteUpdate: ${NB_DISABLE_GEOLITE_UPDATE:-true}"
    echo "  stuns:"
    echo "    - uri: \"${STUN_URI}\""
    echo "  auth:"
    echo "    issuer: \"${AUTH_ISSUER}\""
    echo "    localAuthDisabled: false"
    echo "    sessionCookieEncryptionKey: \"${COOKIE_KEY}\""
    echo "    dashboardRedirectURIs:"
    echo "      - \"${DASHBOARD_URL}/nb-auth\""
    echo "      - \"${DASHBOARD_URL}/nb-silent-auth\""
    echo "    dashboardPostLogoutRedirectURIs:"
    echo "      - \"${DASHBOARD_URL}/\""
    echo "    cliRedirectURIs:"
    echo "      - \"http://localhost:53000/\""
    echo "      - \"http://localhost:54000/\""

    # Seeding the owner here is what makes a throwaway environment loggable-into
    # without a human walking the /setup page first.
    if [[ -n "${NB_OWNER_EMAIL:-}" && -n "${NB_OWNER_PASSWORD:-}" ]]; then
        echo "    owner:"
        echo "      email: \"${NB_OWNER_EMAIL}\""
        echo "      password: \"${NB_OWNER_PASSWORD}\""
    fi

    echo "  store:"
    echo "    engine: \"${STORE_ENGINE}\""
    echo "    dsn: \"${STORE_DSN}\""
    echo "  activityStore:"
    echo "    engine: \"${NB_ACTIVITY_STORE_ENGINE:-${STORE_ENGINE}}\""
    echo "    dsn: \"${NB_ACTIVITY_STORE_DSN:-${STORE_DSN}}\""
    echo "  authStore:"
    echo "    engine: \"${NB_AUTH_STORE_ENGINE:-${STORE_ENGINE}}\""
    echo "    dsn: \"${NB_AUTH_STORE_DSN:-${STORE_DSN}}\""

    # The server sits behind a TLS-terminating load balancer, so the client IP it
    # sees is the proxy's. Trusting the RFC1918 ranges restores the real one from
    # X-Forwarded-For and keeps the peer-registration IP and access logs truthful.
    echo "  reverseProxy:"
    echo "    trustedHTTPProxies:"
    echo "      - \"10.0.0.0/8\""
    echo "      - \"172.16.0.0/12\""
    echo "      - \"192.168.0.0/16\""
    echo "    trustedPeers:"
    echo "      - \"100.64.0.0/10\""
} > "${CONFIG_PATH}"

echo "Rendered ${CONFIG_PATH} (exposedAddress=${EXPOSED_ADDRESS}, dashboard=${DASHBOARD_URL}, store=${STORE_ENGINE})"

exec /go/bin/netbird-server --config "${CONFIG_PATH}" "$@"
