// Package autonoma exposes the Autonoma Environment Factory endpoint, which
// seeds and removes end-to-end test data through the same managers the REST API
// and gRPC server use. Nothing here is reachable without a valid HMAC signature
// over the request body, computed with AUTONOMA_SHARED_SECRET.
package autonoma

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/autonoma-ai/sdk/sdks/go/autonoma"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	proxydomainmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"
	proxymodule "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	"github.com/netbirdio/netbird/management/server/idp"
	nbnetworks "github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/store"
)

const (
	// EndpointPath is where the Environment Factory answers, relative to the
	// API prefix the management router is mounted on.
	EndpointPath = "/autonoma"

	// FullEndpointPath is EndpointPath including the API prefix. It has to be
	// registered as a bypass path: the endpoint authenticates itself with an
	// HMAC over the body and has no user session to present to the JWT
	// middleware.
	FullEndpointPath = "/api" + EndpointPath

	// scopeField is the column every seeded model hangs off. Autonoma reports it
	// in discover so the dashboard knows how test data is tenanted.
	scopeField = "accountId"

	// envSharedSecret signs the request body. Autonoma knows it.
	envSharedSecret = "AUTONOMA_SHARED_SECRET" //nolint:gosec // variable name, not a credential
	// envSigningSecret signs the refs token handed back by "up" and presented
	// again on "down". It never leaves this process.
	envSigningSecret = "AUTONOMA_SIGNING_SECRET"

	// signingSecretDerivationLabel derives a signing secret from the shared one
	// when the environment supplies only the latter. See derivedSigningSecret.
	signingSecretDerivationLabel = "autonoma-refs-token-signing-v1" //nolint:gosec // domain separator, not a credential
)

// Deps carries the managers the factories create through. They are the same
// instances the REST handlers use, so a seeded row goes through the identical
// validation, hashing and event trail as one a user creates.
type Deps struct {
	Store             store.Store
	AccountManager    account.Manager
	IdpManager        idp.Manager
	NetworksManager   nbnetworks.Manager
	RoutersManager    routers.Manager
	ResourcesManager  resources.Manager
	ZonesManager      zones.Manager
	RecordsManager    records.Manager
	ServiceManager    rpservice.Manager
	DomainManager     *proxydomainmanager.Manager
	AccessLogsManager accesslogs.Manager
	ProxyManager      proxymodule.Manager
	AgentNetwork      agentnetwork.Manager
}

// RegisterEndpoints mounts the Environment Factory handler on the management
// API router. It is a no-op when AUTONOMA_SHARED_SECRET is unset, which is the
// case for every deployment that does not run Autonoma's suites.
func RegisterEndpoints(router *mux.Router, deps Deps) {
	sharedSecret := os.Getenv(envSharedSecret)
	if sharedSecret == "" {
		log.Debugf("autonoma: %s is not set, environment factory endpoint not registered", envSharedSecret)
		return
	}

	signingSecret := os.Getenv(envSigningSecret)
	if signingSecret == "" {
		signingSecret = derivedSigningSecret(sharedSecret)
	}
	if signingSecret == sharedSecret {
		log.Errorf("autonoma: %s must differ from %s, environment factory endpoint not registered", envSigningSecret, envSharedSecret)
		return
	}

	f := &factories{deps: deps}
	config := &autonoma.HandlerConfig{
		ScopeField:    scopeField,
		SharedSecret:  sharedSecret,
		SigningSecret: signingSecret,
		SDK:           &autonoma.SdkInfo{Language: "go", Orm: "gorm", Server: "gorilla/mux"},
		Factories:     f.registry(),
		Auth:          f.auth,
	}

	if err := bypass.AddBypassPath(FullEndpointPath); err != nil {
		log.Errorf("autonoma: add bypass path %s: %v", FullEndpointPath, err)
		return
	}

	router.HandleFunc(EndpointPath, handlerFunc(config)).Methods(http.MethodPost, http.MethodOptions)
	log.Infof("autonoma: environment factory endpoint registered on %s", FullEndpointPath)
}

// handlerFunc adapts net/http to the SDK's transport-agnostic entry point. The
// SDK verifies the signature itself; nothing is parsed before it does.
func handlerFunc(config *autonoma.HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(r.Context(), w, http.StatusInternalServerError,
				map[string]any{"error": "read request body", "code": "INTERNAL_ERROR"})
			return
		}

		headers := make(map[string]string, len(r.Header))
		for key, values := range r.Header {
			if len(values) > 0 {
				headers[strings.ToLower(key)] = values[0]
			}
		}

		result := autonoma.HandleRequest(config, autonoma.HandlerRequest{
			Body:    string(body),
			Headers: headers,
		})
		writeJSON(r.Context(), w, result.Status, result.Body)
	}
}

// derivedSigningSecret produces a signing secret from the shared secret when the
// environment provides only the shared one, which is how Autonoma's own preview
// bundles are provisioned. Setting AUTONOMA_SIGNING_SECRET explicitly gives the
// refs token a key Autonoma has never seen and is preferred; deriving keeps the
// token stable across restarts, which a per-process random value would not.
func derivedSigningSecret(sharedSecret string) string {
	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write([]byte(signingSecretDerivationLabel))
	return hex.EncodeToString(mac.Sum(nil))
}

// factories owns the per-model create and teardown functions.
type factories struct {
	deps Deps
}

// ctx returns the context factories run their manager calls under. The request
// context is not threaded through: the SDK's handler signature does not carry
// one, and a seed that outlives a cancelled HTTP request is preferable to a
// half-created account.
func (f *factories) ctx() context.Context {
	return context.Background()
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := writeJSONBody(w, body); err != nil {
		log.WithContext(ctx).Errorf("autonoma: write response: %v", err)
	}
}

// accountRef finds the Account record a child row belongs to so factories can
// act as the account owner, which is the identity the dashboard would use.
func accountOwner(ctx autonoma.FactoryContext, accountID string) (string, error) {
	for _, record := range ctx.Refs["Account"] {
		if id, _ := record["id"].(string); id == accountID {
			if owner, _ := record["ownerUserId"].(string); owner != "" {
				return owner, nil
			}
		}
	}
	return "", fmt.Errorf("no seeded Account %q in this payload: every record must reference its account with _ref", accountID)
}

// refField reads a field off an already-created record of another model. It is
// how a factory reaches a value of its parent that is not the parent's id - the
// only thing a recipe's _ref resolves to.
func refField(ctx autonoma.FactoryContext, model, id, field string) string {
	for _, record := range ctx.Refs[model] {
		if recordID, _ := record["id"].(string); recordID == id {
			value, _ := record[field].(string)
			return value
		}
	}
	return ""
}
