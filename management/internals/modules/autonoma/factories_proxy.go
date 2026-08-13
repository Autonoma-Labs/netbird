package autonoma

import (
	"context"
	"fmt"
	"time"

	"github.com/autonoma-ai/sdk/sdks/go/autonoma"
	"github.com/google/uuid"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	proxymodule "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/types"
)

// ProxyInput registers a reverse-proxy instance against the account, which is
// what a proxy does when it dials management and announces its cluster. Domains
// and services can only be created on a cluster that has a live proxy, so this
// is the root of the reverse-proxy chain.
type ProxyInput struct {
	AccountID string `json:"accountId"`
	// ClusterAddress is the hostname the cluster serves. It is the parent of
	// every service domain published on it and must be unique per run.
	ClusterAddress string `json:"clusterAddress"`
	IPAddress      string `json:"ipAddress"`
	// SupportsCustomPorts and RequireSubdomain mirror the capability flags a
	// real proxy reports on connect.
	SupportsCustomPorts bool `json:"supportsCustomPorts,omitempty"`
	RequireSubdomain    bool `json:"requireSubdomain,omitempty"`
}

func (f *factories) proxyFactory(in *ProxyInput, _ autonoma.FactoryContext) (map[string]any, error) {
	accountID := in.AccountID
	proxyID := "nbproxy-" + uuid.New().String()

	connected, err := f.deps.ProxyManager.Connect(f.ctx(), proxyID, uuid.New().String(),
		in.ClusterAddress, in.IPAddress, &accountID, &proxymodule.Capabilities{
			SupportsCustomPorts: &in.SupportsCustomPorts,
			RequireSubdomain:    &in.RequireSubdomain,
		})
	if err != nil {
		return nil, fmt.Errorf("connect proxy on cluster %s: %w", in.ClusterAddress, err)
	}

	return map[string]any{
		"id":             connected.ID,
		"accountId":      accountID,
		"clusterAddress": connected.ClusterAddress,
		"sessionId":      connected.SessionID,
	}, nil
}

func (f *factories) proxyTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	return ignoreNotFound(f.deps.ProxyManager.DeleteAccountCluster(f.ctx(),
		recordString(record, "clusterAddress"), recordString(record, "accountId")))
}

// DomainInput registers a domain the account may publish services under. The
// domain is unique across every account, so the recipe makes it per-run.
type DomainInput struct {
	AccountID string `json:"accountId"`
	Domain    string `json:"domain"`
	// ProxyID references the seeded Proxy whose cluster serves this domain. Only
	// a cluster with a live proxy in the account is accepted, so the reference
	// both supplies the cluster address and orders the two creates.
	ProxyID string `json:"proxyId"`
}

func (f *factories) domainFactory(in *DomainInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	cluster := refField(ctx, "Proxy", in.ProxyID, "clusterAddress")
	if cluster == "" {
		return nil, fmt.Errorf("no seeded Proxy %q in this payload: a domain needs a live cluster", in.ProxyID)
	}

	created, err := f.deps.DomainManager.CreateDomain(f.ctx(), in.AccountID, owner, in.Domain, cluster)
	if err != nil {
		return nil, fmt.Errorf("create domain %s: %w", in.Domain, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"domain":    created.Domain,
	}, nil
}

func (f *factories) domainTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.DomainManager.DeleteDomain(f.ctx(), accountID, owner, recordString(record, "id")))
}

// ServiceTargetInput is one upstream behind a service. Targets are written by
// the service's own create call rather than as a model of their own.
type ServiceTargetInput struct {
	// TargetType is peer, host, subnet, domain or cluster.
	TargetType string `json:"targetType"`
	// TargetID references the peer or network resource the target points at.
	TargetID string `json:"targetId"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Enabled  bool   `json:"enabled"`
}

// ServiceInput exposes an internal upstream on a registered domain.
type ServiceInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// DomainID references the seeded Domain the service is published under.
	DomainID string `json:"domainId"`
	// Subdomain is prepended to that domain to form the host the service answers
	// on, which is unique across every account.
	Subdomain      string               `json:"subdomain"`
	Enabled        bool                 `json:"enabled"`
	PassHostHeader bool                 `json:"passHostHeader,omitempty"`
	Targets        []ServiceTargetInput `json:"targets"`
}

func (f *factories) serviceFactory(in *ServiceInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	targets := make([]*rpservice.Target, 0, len(in.Targets))
	for _, target := range in.Targets {
		protocol := target.Protocol
		if protocol == "" {
			protocol = "http"
		}
		targets = append(targets, &rpservice.Target{
			AccountID:  in.AccountID,
			TargetType: rpservice.TargetType(target.TargetType),
			TargetId:   target.TargetID,
			Host:       target.Host,
			Port:       target.Port,
			Protocol:   protocol,
			Enabled:    target.Enabled,
		})
	}

	parent := refField(ctx, "Domain", in.DomainID, "domain")
	if parent == "" {
		return nil, fmt.Errorf("no seeded Domain %q in this payload: a service needs a registered domain", in.DomainID)
	}
	host := parent
	if in.Subdomain != "" {
		host = in.Subdomain + "." + parent
	}

	svc := &rpservice.Service{
		AccountID:      in.AccountID,
		Name:           in.Name,
		Domain:         host,
		Enabled:        in.Enabled,
		PassHostHeader: in.PassHostHeader,
		Targets:        targets,
		Mode:           "http",
		Source:         rpservice.SourcePermanent,
	}

	created, err := f.deps.ServiceManager.CreateService(f.ctx(), in.AccountID, owner, svc)
	if err != nil {
		return nil, fmt.Errorf("create service %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"name":      created.Name,
		"domain":    created.Domain,
	}, nil
}

func (f *factories) serviceTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.ServiceManager.DeleteService(f.ctx(), accountID, owner, recordString(record, "id")))
}

// ProxyAccessTokenInput mints an account-scoped proxy token. The REST handler
// builds the record inline rather than through a service, so the factory
// replicates that write: mint through the canonical generator and persist it,
// without the handler's request parsing and permission lookup.
type ProxyAccessTokenInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// ExpiresInMinutes is an offset from seeding time. The proxy rejects the
	// token once it passes; zero means the token never expires.
	ExpiresInMinutes int64 `json:"expiresInMinutes,omitempty"`
}

func (f *factories) proxyAccessTokenFactory(in *ProxyAccessTokenInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	accountID := in.AccountID
	generated, err := types.CreateNewProxyAccessToken(in.Name, minutesToDuration(in.ExpiresInMinutes), &accountID, owner)
	if err != nil {
		return nil, fmt.Errorf("generate proxy access token %s: %w", in.Name, err)
	}

	if err := f.deps.Store.SaveProxyAccessToken(f.ctx(), &generated.ProxyAccessToken); err != nil {
		return nil, fmt.Errorf("save proxy access token %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        generated.ID,
		"accountId": in.AccountID,
		"name":      generated.Name,
		"token":     string(generated.PlainToken),
	}, nil
}

// proxyAccessTokenDeleter and accessLogDeleter are satisfied by the SQL store.
// Neither row has a delete path in the application: tokens are revoked rather
// than removed and access logs age out on a retention sweep.
type proxyAccessTokenDeleter interface {
	DeleteProxyAccessToken(ctx context.Context, accountID, tokenID string) error
}

type accessLogDeleter interface {
	DeleteAccessLogEntry(ctx context.Context, accountID, entryID string) error
}

func (f *factories) proxyAccessTokenTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	deleter, ok := f.deps.Store.(proxyAccessTokenDeleter)
	if !ok {
		return fmt.Errorf("store %T cannot delete proxy access tokens", f.deps.Store)
	}
	return ignoreNotFound(deleter.DeleteProxyAccessToken(f.ctx(),
		recordString(record, "accountId"), recordString(record, "id")))
}

// AccessLogEntryInput records one request served by the reverse proxy.
type AccessLogEntryInput struct {
	AccountID string `json:"accountId"`
	ServiceID string `json:"serviceId"`
	UserID    string `json:"userId"`
	// TimestampMinutes is an offset from seeding time, negative for the past.
	// The access-log surface filters and orders by it, so it cannot be an
	// instant: a fixed date drifts out of every default time range.
	TimestampMinutes int64  `json:"timestampMinutes"`
	Method           string `json:"method"`
	Host             string `json:"host"`
	Path             string `json:"path"`
	StatusCode       int    `json:"statusCode"`
	DurationMillis   int64  `json:"durationMillis"`
	BytesUpload      int64  `json:"bytesUpload"`
	BytesDownload    int64  `json:"bytesDownload"`
	AuthMethodUsed   string `json:"authMethodUsed,omitempty"`
}

func (f *factories) accessLogEntryFactory(in *AccessLogEntryInput, _ autonoma.FactoryContext) (map[string]any, error) {
	entry := &accesslogs.AccessLogEntry{
		ID:             uuid.New().String(),
		AccountID:      in.AccountID,
		ServiceID:      in.ServiceID,
		Timestamp:      fromNow(in.TimestampMinutes),
		Method:         in.Method,
		Host:           in.Host,
		Path:           in.Path,
		Duration:       time.Duration(in.DurationMillis) * time.Millisecond,
		StatusCode:     in.StatusCode,
		UserId:         in.UserID,
		AuthMethodUsed: in.AuthMethodUsed,
		BytesUpload:    in.BytesUpload,
		BytesDownload:  in.BytesDownload,
		Protocol:       accesslogs.AccessLogProtocolHTTP,
	}

	if err := f.deps.AccessLogsManager.SaveAccessLog(f.ctx(), entry); err != nil {
		return nil, fmt.Errorf("save access log entry: %w", err)
	}

	return map[string]any{
		"id":        entry.ID,
		"accountId": in.AccountID,
		"serviceId": in.ServiceID,
	}, nil
}

func (f *factories) accessLogEntryTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	deleter, ok := f.deps.Store.(accessLogDeleter)
	if !ok {
		return fmt.Errorf("store %T cannot delete access log entries", f.deps.Store)
	}
	return ignoreNotFound(deleter.DeleteAccessLogEntry(f.ctx(),
		recordString(record, "accountId"), recordString(record, "id")))
}
