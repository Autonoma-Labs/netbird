package autonoma

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/autonoma-ai/sdk/sdks/go/autonoma"
	"github.com/google/uuid"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agenttypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/server/store"
)

// ProviderInput registers an upstream AI provider for the account.
type ProviderInput struct {
	AccountID string `json:"accountId"`
	// ProviderID names the catalog entry, e.g. openai or anthropic.
	ProviderID  string `json:"providerId"`
	Name        string `json:"name"`
	UpstreamURL string `json:"upstreamUrl"`
	// APIKey is rejected when blank: a provider with no key produces a gateway
	// that fails every upstream request.
	APIKey  string `json:"apiKey"`
	Enabled bool   `json:"enabled"`
}

func (f *factories) providerFactory(in *ProviderInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	created, err := f.deps.AgentNetwork.CreateProvider(f.ctx(), owner, &agenttypes.Provider{
		AccountID:   in.AccountID,
		ProviderID:  in.ProviderID,
		Name:        in.Name,
		UpstreamURL: in.UpstreamURL,
		APIKey:      in.APIKey,
		Enabled:     in.Enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("create agent network provider %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":         created.ID,
		"accountId":  in.AccountID,
		"name":       created.Name,
		"providerId": created.ProviderID,
	}, nil
}

func (f *factories) providerTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AgentNetwork.DeleteProvider(f.ctx(), accountID, owner, recordString(record, "id")))
}

// AgentNetworkPolicyInput authorises groups to reach providers, optionally under
// token and spend caps.
type AgentNetworkPolicyInput struct {
	AccountID              string   `json:"accountId"`
	Name                   string   `json:"name"`
	Description            string   `json:"description,omitempty"`
	Enabled                bool     `json:"enabled"`
	SourceGroups           []string `json:"sourceGroups"`
	DestinationProviderIDs []string `json:"destinationProviderIds"`
	GuardrailIDs           []string `json:"guardrailIds,omitempty"`
	// TokenLimitEnabled and its caps are evaluated over a rolling window, so
	// they are durations rather than instants.
	TokenLimitEnabled   bool    `json:"tokenLimitEnabled,omitempty"`
	TokenGroupCap       int64   `json:"tokenGroupCap,omitempty"`
	TokenUserCap        int64   `json:"tokenUserCap,omitempty"`
	TokenWindowSeconds  int64   `json:"tokenWindowSeconds,omitempty"`
	BudgetLimitEnabled  bool    `json:"budgetLimitEnabled,omitempty"`
	BudgetGroupCapUSD   float64 `json:"budgetGroupCapUsd,omitempty"`
	BudgetUserCapUSD    float64 `json:"budgetUserCapUsd,omitempty"`
	BudgetWindowSeconds int64   `json:"budgetWindowSeconds,omitempty"`
}

func (f *factories) agentNetworkPolicyFactory(in *AgentNetworkPolicyInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	created, err := f.deps.AgentNetwork.CreatePolicy(f.ctx(), owner, &agenttypes.Policy{
		AccountID:              in.AccountID,
		Name:                   in.Name,
		Description:            in.Description,
		Enabled:                in.Enabled,
		SourceGroups:           in.SourceGroups,
		DestinationProviderIDs: in.DestinationProviderIDs,
		GuardrailIDs:           in.GuardrailIDs,
		Limits: agenttypes.PolicyLimits{
			TokenLimit: agenttypes.PolicyTokenLimit{
				Enabled:       in.TokenLimitEnabled,
				GroupCap:      in.TokenGroupCap,
				UserCap:       in.TokenUserCap,
				WindowSeconds: in.TokenWindowSeconds,
			},
			BudgetLimit: agenttypes.PolicyBudgetLimit{
				Enabled:       in.BudgetLimitEnabled,
				GroupCapUsd:   in.BudgetGroupCapUSD,
				UserCapUsd:    in.BudgetUserCapUSD,
				WindowSeconds: in.BudgetWindowSeconds,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create agent network policy %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"name":      created.Name,
	}, nil
}

func (f *factories) agentNetworkPolicyTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AgentNetwork.DeletePolicy(f.ctx(), accountID, owner, recordString(record, "id")))
}

// GuardrailInput creates a reusable model allowlist and prompt-capture setting.
type GuardrailInput struct {
	AccountID            string   `json:"accountId"`
	Name                 string   `json:"name"`
	Description          string   `json:"description,omitempty"`
	ModelAllowlist       []string `json:"modelAllowlist,omitempty"`
	ModelAllowlistOn     bool     `json:"modelAllowlistEnabled,omitempty"`
	PromptCaptureEnabled bool     `json:"promptCaptureEnabled,omitempty"`
	RedactPii            bool     `json:"redactPii,omitempty"`
}

func (f *factories) guardrailFactory(in *GuardrailInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	models := in.ModelAllowlist
	if models == nil {
		models = []string{}
	}

	created, err := f.deps.AgentNetwork.CreateGuardrail(f.ctx(), owner, &agenttypes.Guardrail{
		AccountID:   in.AccountID,
		Name:        in.Name,
		Description: in.Description,
		Checks: agenttypes.GuardrailChecks{
			ModelAllowlist: agenttypes.GuardrailModelAllowlist{
				Enabled: in.ModelAllowlistOn,
				Models:  models,
			},
			PromptCapture: agenttypes.GuardrailPromptCapture{
				Enabled:   in.PromptCaptureEnabled,
				RedactPii: in.RedactPii,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create guardrail %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"name":      created.Name,
	}, nil
}

func (f *factories) guardrailTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AgentNetwork.DeleteGuardrail(f.ctx(), accountID, owner, recordString(record, "id")))
}

// AccountBudgetRuleInput caps account-wide spend over a rolling window.
type AccountBudgetRuleInput struct {
	AccountID    string   `json:"accountId"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	TargetGroups []string `json:"targetGroups,omitempty"`
	TargetUsers  []string `json:"targetUsers,omitempty"`
	// BudgetWindowSeconds is a rolling window length, not a calendar month: the
	// counters it bounds are keyed on windows aligned to it at request time.
	BudgetWindowSeconds int64   `json:"budgetWindowSeconds"`
	BudgetGroupCapUSD   float64 `json:"budgetGroupCapUsd,omitempty"`
	BudgetUserCapUSD    float64 `json:"budgetUserCapUsd,omitempty"`
}

func (f *factories) budgetRuleFactory(in *AccountBudgetRuleInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	created, err := f.deps.AgentNetwork.CreateBudgetRule(f.ctx(), owner, &agenttypes.AccountBudgetRule{
		AccountID:    in.AccountID,
		Name:         in.Name,
		Enabled:      in.Enabled,
		TargetGroups: in.TargetGroups,
		TargetUsers:  in.TargetUsers,
		Limits: agenttypes.PolicyLimits{
			BudgetLimit: agenttypes.PolicyBudgetLimit{
				Enabled:       true,
				GroupCapUsd:   in.BudgetGroupCapUSD,
				UserCapUsd:    in.BudgetUserCapUSD,
				WindowSeconds: in.BudgetWindowSeconds,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create budget rule %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"name":      created.Name,
	}, nil
}

func (f *factories) budgetRuleTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AgentNetwork.DeleteBudgetRule(f.ctx(), accountID, owner, recordString(record, "id")))
}

// ConsumptionInput books usage against the counters the gateway increments when
// it serves a request, so the account's spend and token dashboards read as if
// traffic had flowed. The counters land in windows aligned at booking time,
// which is why the amounts are given rather than a window instant.
type ConsumptionInput struct {
	AccountID string `json:"accountId"`
	UserID    string `json:"userId"`
	// GroupIDs decide which budget rules the usage is booked against.
	GroupIDs []string `json:"groupIds,omitempty"`
	// BudgetRuleID references the seeded AccountBudgetRule whose window the
	// counters land in. A counter exists only where a rule applies, so without
	// the rule already in place this call books nothing at all.
	BudgetRuleID string  `json:"budgetRuleId"`
	TokensIn     int64   `json:"tokensIn"`
	TokensOut    int64   `json:"tokensOut"`
	CostUSD      float64 `json:"costUsd"`
}

func (f *factories) consumptionFactory(in *ConsumptionInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	if refField(ctx, "AccountBudgetRule", in.BudgetRuleID, "id") == "" {
		return nil, fmt.Errorf("no seeded AccountBudgetRule %q in this payload: usage is only counted where a rule applies", in.BudgetRuleID)
	}

	if err := f.deps.AgentNetwork.RecordAccountBudgetUsage(f.ctx(), in.AccountID, in.UserID,
		in.GroupIDs, in.TokensIn, in.TokensOut, in.CostUSD); err != nil {
		return nil, fmt.Errorf("record agent network consumption: %w", err)
	}

	return map[string]any{
		"id":        in.AccountID + ":consumption",
		"accountId": in.AccountID,
	}, nil
}

// consumptionDeleter and agentNetworkAccessLogDeleter are satisfied by the SQL
// store. Consumption counters and agent-network telemetry are aged out by
// retention sweeps rather than deleted individually.
type consumptionDeleter interface {
	DeleteAgentNetworkConsumptionForAccount(ctx context.Context, accountID string) error
}

type agentNetworkAccessLogDeleter interface {
	DeleteAgentNetworkAccessLog(ctx context.Context, accountID, logID string) error
}

func (f *factories) consumptionTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	deleter, ok := f.deps.Store.(consumptionDeleter)
	if !ok {
		return fmt.Errorf("store %T cannot delete agent network consumption", f.deps.Store)
	}
	return ignoreNotFound(deleter.DeleteAgentNetworkConsumptionForAccount(f.ctx(), recordString(record, "accountId")))
}

// AgentNetworkAccessLogInput records one gateway request. It goes in through the
// proxy's own ingest path, which flattens the metadata into the queryable
// columns and derives the usage and authorising-group child rows.
type AgentNetworkAccessLogInput struct {
	AccountID string `json:"accountId"`
	ServiceID string `json:"serviceId"`
	UserID    string `json:"userId"`
	// TimestampMinutes is an offset from seeding time, negative for the past.
	// The Agent Network log and usage views filter on a window ending now.
	TimestampMinutes int64  `json:"timestampMinutes"`
	Provider         string `json:"provider"`
	Model            string `json:"model"`
	SessionID        string `json:"sessionId"`
	// ResolvedProviderID references the seeded Provider row.
	ResolvedProviderID string `json:"resolvedProviderId"`
	SelectedPolicyID   string `json:"selectedPolicyId,omitempty"`
	// Decision is allow or deny.
	Decision string `json:"decision"`
	// AuthorisingGroups are the group ids that let the request through.
	AuthorisingGroups []string `json:"authorisingGroups,omitempty"`
	InputTokens       int64    `json:"inputTokens"`
	OutputTokens      int64    `json:"outputTokens"`
	InputCostUSD      float64  `json:"inputCostUsd"`
	OutputCostUSD     float64  `json:"outputCostUsd"`
	Method            string   `json:"method"`
	Host              string   `json:"host"`
	Path              string   `json:"path"`
	StatusCode        int      `json:"statusCode"`
	DurationMillis    int64    `json:"durationMillis"`
	RequestPrompt     string   `json:"requestPrompt,omitempty"`
	ResponseText      string   `json:"responseText,omitempty"`
}

func (f *factories) agentNetworkAccessLogFactory(in *AgentNetworkAccessLogInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	// Ingest only persists the full log row when the account has agent-network
	// settings with log collection on. A real account gets that row when the
	// gateway is turned on in the dashboard, so the same call bootstraps it here
	// before the first log arrives.
	if err := f.ensureAgentNetworkSettings(in.AccountID, owner); err != nil {
		return nil, err
	}

	groups := ""
	for i, group := range in.AuthorisingGroups {
		if i > 0 {
			groups += ","
		}
		groups += group
	}

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
		AuthMethodUsed: "bearer",
		Protocol:       accesslogs.AccessLogProtocolHTTP,
		AgentNetwork:   true,
		Metadata: map[string]string{
			"llm.provider":              in.Provider,
			"llm.model":                 in.Model,
			"llm.session_id":            in.SessionID,
			"llm.resolved_provider_id":  in.ResolvedProviderID,
			"llm.selected_policy_id":    in.SelectedPolicyID,
			"llm_policy.decision":       in.Decision,
			"llm.input_tokens":          strconv.FormatInt(in.InputTokens, 10),
			"llm.output_tokens":         strconv.FormatInt(in.OutputTokens, 10),
			"llm.total_tokens":          strconv.FormatInt(in.InputTokens+in.OutputTokens, 10),
			"cost.usd_input":            strconv.FormatFloat(in.InputCostUSD, 'f', -1, 64),
			"cost.usd_output":           strconv.FormatFloat(in.OutputCostUSD, 'f', -1, 64),
			"llm.authorising_groups":    groups,
			"llm.request_prompt":        in.RequestPrompt,
			"llm.response_completion":   in.ResponseText,
			"llm.cached_input_tokens":   "0",
			"llm.cache_creation_tokens": "0",
		},
	}

	if err := agentnetwork.IngestAccessLog(f.ctx(), f.deps.Store, entry); err != nil {
		return nil, fmt.Errorf("ingest agent network access log: %w", err)
	}

	return map[string]any{
		"id":        entry.ID,
		"accountId": in.AccountID,
		"model":     in.Model,
	}, nil
}

func (f *factories) agentNetworkAccessLogTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	deleter, ok := f.deps.Store.(agentNetworkAccessLogDeleter)
	if !ok {
		return fmt.Errorf("store %T cannot delete agent network access logs", f.deps.Store)
	}
	return ignoreNotFound(deleter.DeleteAgentNetworkAccessLog(f.ctx(),
		recordString(record, "accountId"), recordString(record, "id")))
}

// ensureAgentNetworkSettings bootstraps the account's gateway settings if the
// account has none, using a per-account endpoint so concurrent runs never
// contend on the globally unique domain index.
func (f *factories) ensureAgentNetworkSettings(accountID, owner string) error {
	if _, err := f.deps.Store.GetAgentNetworkSettings(f.ctx(), store.LockingStrengthNone, accountID); err == nil {
		return nil
	}

	endpoint := "gw-" + accountID + ".agent.netbird.test"
	settings := &agenttypes.Settings{
		AccountID:              accountID,
		EnableLogCollection:    true,
		EnablePromptCollection: true,
		AccessLogRetentionDays: 30,
	}
	if _, err := f.deps.AgentNetwork.CreateSettings(f.ctx(), owner, settings, "", endpoint); err != nil {
		return fmt.Errorf("bootstrap agent network settings: %w", err)
	}
	return nil
}
