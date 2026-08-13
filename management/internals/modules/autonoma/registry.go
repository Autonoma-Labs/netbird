package autonoma

import (
	"github.com/autonoma-ai/sdk/sdks/go/autonoma"
)

// registry names one factory per model the entity audit says can be created on
// its own. Models the application only ever mints as part of a parent's create
// - a policy's rules, a service's targets, the extra settings and onboarding
// rows provisioning writes with the account, a peer's network addresses, and the
// group, usage and usage-group children the agent-network ingest derives - have
// no entry: they arrive with their parent and leave with its teardown.
func (f *factories) registry() autonoma.FactoryRegistry {
	return autonoma.FactoryRegistry{
		// Tenant and identity.
		"Account":             defineFactory(f.accountFactory, f.accountTeardown),
		"Settings":            defineFactory(f.settingsFactory, nil),
		"installation":        defineFactory(f.installationFactory, f.installationTeardown),
		"User":                defineFactory(f.userFactory, f.userTeardown),
		"PersonalAccessToken": defineFactory(f.patFactory, f.patTeardown),
		"UserInviteRecord":    defineFactory(f.userInviteFactory, f.userInviteTeardown),

		// Overlay network.
		"Group":           defineFactory(f.groupFactory, f.groupTeardown),
		"Peer":            defineFactory(f.peerFactory, f.peerTeardown),
		"GroupPeer":       defineFactory(f.groupPeerFactory, f.groupPeerTeardown),
		"SetupKey":        defineFactory(f.setupKeyFactory, f.setupKeyTeardown),
		"Policy":          defineFactory(f.policyFactory, f.policyTeardown),
		"Checks":          defineFactory(f.checksFactory, f.checksTeardown),
		"Route":           defineFactory(f.routeFactory, f.routeTeardown),
		"NameServerGroup": defineFactory(f.nameServerGroupFactory, f.nameServerGroupTeardown),
		"Network":         defineFactory(f.networkFactory, f.networkTeardown),
		"NetworkRouter":   defineFactory(f.networkRouterFactory, f.networkRouterTeardown),
		"NetworkResource": defineFactory(f.networkResourceFactory, f.networkResourceTeardown),
		"Job":             defineFactory(f.jobFactory, f.jobTeardown),

		// Private DNS.
		"Zone":   defineFactory(f.zoneFactory, f.zoneTeardown),
		"Record": defineFactory(f.recordFactory, f.recordTeardown),

		// Reverse proxy.
		"Proxy":            defineFactory(f.proxyFactory, f.proxyTeardown),
		"Domain":           defineFactory(f.domainFactory, f.domainTeardown),
		"Service":          defineFactory(f.serviceFactory, f.serviceTeardown),
		"ProxyAccessToken": defineFactory(f.proxyAccessTokenFactory, f.proxyAccessTokenTeardown),
		"AccessLogEntry":   defineFactory(f.accessLogEntryFactory, f.accessLogEntryTeardown),

		// Agent Network.
		"Provider":              defineFactory(f.providerFactory, f.providerTeardown),
		"AgentNetworkPolicy":    defineFactory(f.agentNetworkPolicyFactory, f.agentNetworkPolicyTeardown),
		"Guardrail":             defineFactory(f.guardrailFactory, f.guardrailTeardown),
		"AccountBudgetRule":     defineFactory(f.budgetRuleFactory, f.budgetRuleTeardown),
		"Consumption":           defineFactory(f.consumptionFactory, f.consumptionTeardown),
		"AgentNetworkAccessLog": defineFactory(f.agentNetworkAccessLogFactory, f.agentNetworkAccessLogTeardown),
	}
}
