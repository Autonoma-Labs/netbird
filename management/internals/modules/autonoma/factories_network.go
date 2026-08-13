package autonoma

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/autonoma-ai/sdk/sdks/go/autonoma"
	"github.com/google/uuid"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	nbroute "github.com/netbirdio/netbird/route"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// GroupInput creates a peer group.
type GroupInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// PeerIDs are added as members during creation, which is the same path the
	// dashboard takes when a group is created with peers already selected.
	PeerIDs []string `json:"peerIds,omitempty"`
}

func (f *factories) groupFactory(in *GroupInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	group := &types.Group{
		AccountID: in.AccountID,
		Name:      in.Name,
		Issued:    types.GroupIssuedAPI,
		Peers:     in.PeerIDs,
	}
	if err := f.deps.AccountManager.CreateGroup(f.ctx(), in.AccountID, owner, group); err != nil {
		return nil, fmt.Errorf("create group %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        group.ID,
		"accountId": in.AccountID,
		"name":      group.Name,
	}, nil
}

func (f *factories) groupTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeleteGroup(f.ctx(), accountID, owner, recordString(record, "id")))
}

// PeerInput registers a device. The overlay address and DNS label are allocated
// by the account manager, so the recipe does not supply them.
type PeerInput struct {
	AccountID string `json:"accountId"`
	// UserID is the user the peer is registered against. Empty registers it
	// against the account owner.
	UserID string `json:"userId,omitempty"`
	// Hostname becomes the peer name and the basis of its DNS label.
	Hostname string `json:"hostname"`
	// GoOS is the operating system as the agent reports it: linux, darwin or
	// windows.
	GoOS      string `json:"goOS"`
	OSVersion string `json:"osVersion,omitempty"`
	// WtVersion is the agent version shown in the peers table.
	WtVersion  string `json:"wtVersion,omitempty"`
	SSHEnabled bool   `json:"sshEnabled,omitempty"`
	// Connected marks the peer online. The peers list partitions on it, so it is
	// applied after registration through the same status write the gRPC stream
	// performs when an agent connects.
	Connected bool `json:"connected,omitempty"`
	// LastSeenMinutes is an offset from seeding time, negative for the past. The
	// peers list renders "last seen" relative to now, so it cannot be an instant.
	LastSeenMinutes int64 `json:"lastSeenMinutes,omitempty"`
	// LocalAddress is the peer's address on its own LAN, reported in system meta.
	LocalAddress string `json:"localAddress,omitempty"`
}

func (f *factories) peerFactory(in *PeerInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}
	userID := in.UserID
	if userID == "" {
		userID = owner
	}

	// The peers table has a global unique index on the public key, so it is
	// minted per peer rather than supplied by the recipe.
	peerKey, err := randomPeerKey()
	if err != nil {
		return nil, err
	}

	meta := nbpeer.PeerSystemMeta{
		Hostname:  in.Hostname,
		GoOS:      in.GoOS,
		OS:        in.GoOS,
		OSVersion: in.OSVersion,
		WtVersion: in.WtVersion,
		Kernel:    in.GoOS,
		Platform:  "x86_64",
	}
	if in.LocalAddress != "" {
		addr, parseErr := netip.ParseAddr(in.LocalAddress)
		if parseErr != nil {
			return nil, fmt.Errorf("parse localAddress %q: %w", in.LocalAddress, parseErr)
		}
		meta.NetworkAddresses = []nbpeer.NetworkAddress{{
			NetIP: netip.PrefixFrom(addr.Unmap(), addr.BitLen()),
			Mac:   randomMAC(),
		}}
	}

	created, _, _, _, err := f.deps.AccountManager.AddPeer(f.ctx(), in.AccountID, "", userID, &nbpeer.Peer{
		Key:  peerKey,
		Meta: meta,
	}, false)
	if err != nil {
		return nil, fmt.Errorf("add peer %s: %w", in.Hostname, err)
	}

	if in.SSHEnabled {
		created.SSHEnabled = true
		if _, err := f.deps.AccountManager.UpdatePeer(f.ctx(), in.AccountID, owner, created); err != nil {
			return nil, fmt.Errorf("enable ssh on peer %s: %w", in.Hostname, err)
		}
	}

	lastSeen := fromNow(in.LastSeenMinutes)
	if err := f.deps.Store.SavePeerStatus(f.ctx(), in.AccountID, created.ID, nbpeer.PeerStatus{
		Connected:        in.Connected,
		LastSeen:         lastSeen,
		LoginExpired:     false,
		RequiresApproval: false,
	}); err != nil {
		return nil, fmt.Errorf("set status on peer %s: %w", in.Hostname, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"name":      created.Name,
		"ip":        created.IP.String(),
		"dnsLabel":  created.DNSLabel,
		"key":       peerKey,
	}, nil
}

func (f *factories) peerTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeletePeer(f.ctx(), accountID, recordString(record, "id"), owner))
}

// GroupPeerInput adds an existing peer to an existing group.
type GroupPeerInput struct {
	AccountID string `json:"accountId"`
	GroupID   string `json:"groupId"`
	PeerID    string `json:"peerId"`
}

func (f *factories) groupPeerFactory(in *GroupPeerInput, _ autonoma.FactoryContext) (map[string]any, error) {
	if err := f.deps.AccountManager.GroupAddPeer(f.ctx(), in.AccountID, in.GroupID, in.PeerID); err != nil {
		return nil, fmt.Errorf("add peer %s to group %s: %w", in.PeerID, in.GroupID, err)
	}
	return map[string]any{
		"id":        in.GroupID + ":" + in.PeerID,
		"accountId": in.AccountID,
		"groupId":   in.GroupID,
		"peerId":    in.PeerID,
	}, nil
}

func (f *factories) groupPeerTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	return ignoreNotFound(f.deps.AccountManager.GroupDeletePeer(f.ctx(),
		recordString(record, "accountId"), recordString(record, "groupId"), recordString(record, "peerId")))
}

// SetupKeyInput mints a registration key.
type SetupKeyInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// KeyType is "one-off" or "reusable".
	KeyType string `json:"keyType"`
	// ValidForMinutes is an offset from seeding time. A negative value seeds a
	// key that is already expired, which is how the expired row in the setup-key
	// list is produced; zero seeds a key that never expires.
	ValidForMinutes int64    `json:"validForMinutes"`
	UsageLimit      int      `json:"usageLimit,omitempty"`
	AutoGroups      []string `json:"autoGroups,omitempty"`
	Ephemeral       bool     `json:"ephemeral,omitempty"`
}

func (f *factories) setupKeyFactory(in *SetupKeyInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	autoGroups := in.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	key, err := f.deps.AccountManager.CreateSetupKey(f.ctx(), in.AccountID, in.Name,
		types.SetupKeyType(in.KeyType), minutesToDuration(in.ValidForMinutes), autoGroups,
		in.UsageLimit, owner, in.Ephemeral, false)
	if err != nil {
		return nil, fmt.Errorf("create setup key %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        key.Id,
		"accountId": in.AccountID,
		"name":      key.Name,
		"key":       key.Key,
	}, nil
}

func (f *factories) setupKeyTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeleteSetupKey(f.ctx(), accountID, owner, recordString(record, "id")))
}

// PolicyRuleInput is one rule inside a policy. Rules are not created on their
// own: SavePolicy writes the policy and its rules in a single call, so they
// arrive nested rather than as their own top-level model.
type PolicyRuleInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	// Action is "accept" or "drop".
	Action string `json:"action"`
	// Protocol is all, tcp, udp, icmp or netbird-ssh.
	Protocol      string   `json:"protocol"`
	Sources       []string `json:"sources"`
	Destinations  []string `json:"destinations"`
	Bidirectional bool     `json:"bidirectional"`
	Ports         []string `json:"ports,omitempty"`
}

// PolicyInput creates an access-control policy together with its rules.
type PolicyInput struct {
	AccountID           string            `json:"accountId"`
	Name                string            `json:"name"`
	Description         string            `json:"description,omitempty"`
	Enabled             bool              `json:"enabled"`
	Rules               []PolicyRuleInput `json:"rules"`
	SourcePostureChecks []string          `json:"sourcePostureChecks,omitempty"`
}

func (f *factories) policyFactory(in *PolicyInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	rules := make([]*sharedtypes.PolicyRule, 0, len(in.Rules))
	for _, rule := range in.Rules {
		rules = append(rules, &sharedtypes.PolicyRule{
			Name:          rule.Name,
			Description:   rule.Description,
			Enabled:       rule.Enabled,
			Action:        sharedtypes.PolicyTrafficActionType(rule.Action),
			Protocol:      sharedtypes.PolicyRuleProtocolType(rule.Protocol),
			Sources:       rule.Sources,
			Destinations:  rule.Destinations,
			Bidirectional: rule.Bidirectional,
			Ports:         rule.Ports,
		})
	}

	policy := &sharedtypes.Policy{
		AccountID:           in.AccountID,
		Name:                in.Name,
		Description:         in.Description,
		Enabled:             in.Enabled,
		Rules:               rules,
		SourcePostureChecks: in.SourcePostureChecks,
	}

	saved, err := f.deps.AccountManager.SavePolicy(f.ctx(), in.AccountID, owner, policy, true)
	if err != nil {
		return nil, fmt.Errorf("create policy %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        saved.ID,
		"accountId": in.AccountID,
		"name":      saved.Name,
	}, nil
}

func (f *factories) policyTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeletePolicy(f.ctx(), accountID, recordString(record, "id"), owner))
}

// ChecksInput creates a posture check.
type ChecksInput struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// MinDarwinVersion, MinLinuxKernel and MinWindowsKernel populate the OS
	// version check. Any subset may be given.
	MinDarwinVersion string `json:"minDarwinVersion,omitempty"`
	MinLinuxKernel   string `json:"minLinuxKernel,omitempty"`
	MinWindowsKernel string `json:"minWindowsKernel,omitempty"`
	// MinNBVersion populates the agent version check instead.
	MinNBVersion string `json:"minNbVersion,omitempty"`
}

func (f *factories) checksFactory(in *ChecksInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	definition := posture.ChecksDefinition{}
	if in.MinDarwinVersion != "" || in.MinLinuxKernel != "" || in.MinWindowsKernel != "" {
		osCheck := &posture.OSVersionCheck{}
		if in.MinDarwinVersion != "" {
			osCheck.Darwin = &posture.MinVersionCheck{MinVersion: in.MinDarwinVersion}
		}
		if in.MinLinuxKernel != "" {
			osCheck.Linux = &posture.MinKernelVersionCheck{MinKernelVersion: in.MinLinuxKernel}
		}
		if in.MinWindowsKernel != "" {
			osCheck.Windows = &posture.MinKernelVersionCheck{MinKernelVersion: in.MinWindowsKernel}
		}
		definition.OSVersionCheck = osCheck
	}
	if in.MinNBVersion != "" {
		definition.NBVersionCheck = &posture.NBVersionCheck{MinVersion: in.MinNBVersion}
	}

	checks := &posture.Checks{
		AccountID:   in.AccountID,
		Name:        in.Name,
		Description: in.Description,
		Checks:      definition,
	}

	saved, err := f.deps.AccountManager.SavePostureChecks(f.ctx(), in.AccountID, owner, checks, true)
	if err != nil {
		return nil, fmt.Errorf("create posture check %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        saved.ID,
		"accountId": in.AccountID,
		"name":      saved.Name,
	}, nil
}

func (f *factories) checksTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeletePostureChecks(f.ctx(), accountID, recordString(record, "id"), owner))
}

// RouteInput publishes a network prefix through a routing peer.
type RouteInput struct {
	AccountID string `json:"accountId"`
	// NetID is the short network identifier shown in the routes table. It is
	// unique per account.
	NetID       string `json:"netId"`
	Description string `json:"description,omitempty"`
	// Network is the routed prefix in CIDR form.
	Network string `json:"network"`
	// PeerID is the routing peer. Mutually exclusive with PeerGroupIDs.
	PeerID       string   `json:"peerId,omitempty"`
	PeerGroupIDs []string `json:"peerGroupIds,omitempty"`
	// Groups are the distribution groups the route is advertised to.
	Groups     []string `json:"groups"`
	Masquerade bool     `json:"masquerade"`
	Metric     int      `json:"metric"`
	Enabled    bool     `json:"enabled"`
}

func (f *factories) routeFactory(in *RouteInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	prefix, err := netip.ParsePrefix(in.Network)
	if err != nil {
		return nil, fmt.Errorf("parse route network %q: %w", in.Network, err)
	}

	metric := in.Metric
	if metric == 0 {
		metric = nbroute.MaxMetric
	}

	created, err := f.deps.AccountManager.CreateRoute(f.ctx(), in.AccountID, prefix, nbroute.IPv4Network,
		nil, in.PeerID, in.PeerGroupIDs, in.Description, nbroute.NetID(in.NetID), in.Masquerade, metric,
		in.Groups, nil, in.Enabled, owner, false, false)
	if err != nil {
		return nil, fmt.Errorf("create route %s: %w", in.NetID, err)
	}

	return map[string]any{
		"id":        string(created.ID),
		"accountId": in.AccountID,
		"netId":     string(created.NetID),
	}, nil
}

func (f *factories) routeTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeleteRoute(f.ctx(), accountID,
		nbroute.ID(recordString(record, "id")), owner))
}

// NameServerGroupInput configures a set of resolvers.
type NameServerGroupInput struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// NameServers are plain IPv4 or IPv6 addresses; the group resolves over UDP
	// on Port, defaulting to 53.
	NameServers          []string `json:"nameServers"`
	Port                 int      `json:"port,omitempty"`
	Groups               []string `json:"groups"`
	Primary              bool     `json:"primary"`
	Domains              []string `json:"domains,omitempty"`
	Enabled              bool     `json:"enabled"`
	SearchDomainsEnabled bool     `json:"searchDomainsEnabled,omitempty"`
}

func (f *factories) nameServerGroupFactory(in *NameServerGroupInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	port := in.Port
	if port == 0 {
		port = 53
	}

	servers := make([]nbdns.NameServer, 0, len(in.NameServers))
	for _, raw := range in.NameServers {
		addr, parseErr := netip.ParseAddr(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("parse nameserver %q: %w", raw, parseErr)
		}
		servers = append(servers, nbdns.NameServer{
			IP:     addr.Unmap(),
			NSType: nbdns.UDPNameServerType,
			Port:   port,
		})
	}

	created, err := f.deps.AccountManager.CreateNameServerGroup(f.ctx(), in.AccountID, in.Name, in.Description,
		servers, in.Groups, in.Primary, in.Domains, in.Enabled, owner, in.SearchDomainsEnabled)
	if err != nil {
		return nil, fmt.Errorf("create nameserver group %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"name":      created.Name,
	}, nil
}

func (f *factories) nameServerGroupTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.AccountManager.DeleteNameServerGroup(f.ctx(), accountID, recordString(record, "id"), owner))
}

// NetworkInput creates a routed network container.
type NetworkInput struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (f *factories) networkFactory(in *NetworkInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	created, err := f.deps.NetworksManager.CreateNetwork(f.ctx(), owner, &networkTypes.Network{
		AccountID:   in.AccountID,
		Name:        in.Name,
		Description: in.Description,
	})
	if err != nil {
		return nil, fmt.Errorf("create network %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"name":      created.Name,
	}, nil
}

func (f *factories) networkTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.NetworksManager.DeleteNetwork(f.ctx(), accountID, owner, recordString(record, "id")))
}

// NetworkRouterInput attaches a routing peer to a network.
type NetworkRouterInput struct {
	AccountID    string   `json:"accountId"`
	NetworkID    string   `json:"networkId"`
	PeerID       string   `json:"peerId,omitempty"`
	PeerGroups   []string `json:"peerGroups,omitempty"`
	Masquerade   bool     `json:"masquerade"`
	Metric       int      `json:"metric"`
	Enabled      bool     `json:"enabled"`
	AutoAllPeers bool     `json:"autoAllPeers,omitempty"`
}

func (f *factories) networkRouterFactory(in *NetworkRouterInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	metric := in.Metric
	if metric == 0 {
		metric = nbroute.MaxMetric
	}

	created, err := f.deps.RoutersManager.CreateRouter(f.ctx(), owner, &routerTypes.NetworkRouter{
		AccountID:  in.AccountID,
		NetworkID:  in.NetworkID,
		Peer:       in.PeerID,
		PeerGroups: in.PeerGroups,
		Masquerade: in.Masquerade,
		Metric:     metric,
		Enabled:    in.Enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("create network router on %s: %w", in.NetworkID, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"networkId": in.NetworkID,
	}, nil
}

func (f *factories) networkRouterTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.RoutersManager.DeleteRouter(f.ctx(), accountID, owner,
		recordString(record, "networkId"), recordString(record, "id")))
}

// NetworkResourceInput publishes a subnet, host or domain inside a network.
type NetworkResourceInput struct {
	AccountID   string `json:"accountId"`
	NetworkID   string `json:"networkId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Address is a CIDR prefix, a single host address or a domain.
	Address string   `json:"address"`
	Groups  []string `json:"groups"`
	Enabled bool     `json:"enabled"`
}

func (f *factories) networkResourceFactory(in *NetworkResourceInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	resource := &resourceTypes.NetworkResource{
		AccountID:   in.AccountID,
		NetworkID:   in.NetworkID,
		Name:        in.Name,
		Description: in.Description,
		Address:     in.Address,
		GroupIDs:    in.Groups,
		Enabled:     in.Enabled,
	}

	created, err := f.deps.ResourcesManager.CreateResource(f.ctx(), owner, resource)
	if err != nil {
		return nil, fmt.Errorf("create network resource %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"networkId": in.NetworkID,
		"name":      created.Name,
	}, nil
}

func (f *factories) networkResourceTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.ResourcesManager.DeleteResource(f.ctx(), accountID, owner,
		recordString(record, "networkId"), recordString(record, "id")))
}

// JobInput queues a debug-bundle job against a peer.
type JobInput struct {
	AccountID string `json:"accountId"`
	PeerID    string `json:"peerId"`
	// LogFileCount is between 1 and 1000.
	LogFileCount int  `json:"logFileCount"`
	Anonymize    bool `json:"anonymize,omitempty"`
	// Completed marks the job finished rather than pending.
	Completed bool `json:"completed,omitempty"`
	// PeerName is recorded on the activity event, the way the manager reads it
	// off the peer row it locks.
	PeerName string `json:"peerName,omitempty"`
}

func (f *factories) jobFactory(in *JobInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	logFileCount := in.LogFileCount
	if logFileCount == 0 {
		logFileCount = 1
	}
	parameters, err := json.Marshal(map[string]any{
		"bundle_for":      false,
		"bundle_for_time": 0,
		"log_file_count":  logFileCount,
		"anonymize":       in.Anonymize,
	})
	if err != nil {
		return nil, err
	}

	job := &types.Job{
		ID:          uuid.New().String(),
		TriggeredBy: owner,
		PeerID:      in.PeerID,
		AccountID:   in.AccountID,
		Status:      types.JobStatusPending,
		CreatedAt:   time.Now().UTC(),
		Workload: types.Workload{
			Type:       types.JobTypeBundle,
			Parameters: parameters,
			Result:     []byte("{}"),
		},
	}
	if in.Completed {
		completedAt := time.Now().UTC()
		job.Status = types.JobStatusSucceeded
		job.CompletedAt = &completedAt
	}

	// AccountManager.CreatePeerJob refuses to write a job unless the peer holds a
	// live gRPC stream, and dispatches the request down it before persisting.
	// A seeded peer has no agent process behind it, so the write is replicated
	// here instead: the same insert the manager runs inside its transaction, plus
	// the activity event it records, without the dispatch and the connectivity
	// gate that only a running agent can satisfy.
	if err := f.deps.Store.CreatePeerJob(f.ctx(), job); err != nil {
		return nil, fmt.Errorf("create peer job on %s: %w", in.PeerID, err)
	}
	f.deps.AccountManager.StoreEvent(f.ctx(), owner, in.PeerID, in.AccountID, activity.JobCreatedByUser,
		map[string]any{"for_peer_name": in.PeerName, "job_type": job.Workload.Type})

	return map[string]any{
		"id":        job.ID,
		"accountId": in.AccountID,
		"peerId":    in.PeerID,
	}, nil
}

// peerJobDeleter is satisfied by the SQL store. Job rows carry no foreign key
// back to the account, so the account teardown cannot reclaim them and they are
// deleted explicitly. The capability is not on store.Store because nothing in
// the application deletes a job.
type peerJobDeleter interface {
	DeletePeerJob(ctx context.Context, accountID, jobID string) error
}

func (f *factories) jobTeardown(record map[string]any, _ autonoma.FactoryContext) error {
	deleter, ok := f.deps.Store.(peerJobDeleter)
	if !ok {
		return fmt.Errorf("store %T cannot delete peer jobs", f.deps.Store)
	}
	return ignoreNotFound(deleter.DeletePeerJob(f.ctx(), recordString(record, "accountId"), recordString(record, "id")))
}

// randomPeerKey mints a value shaped like a base64 overlay public key. Peers are
// uniquely indexed on it across the whole instance, so it can never come from
// the recipe.
func randomPeerKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate peer key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func randomMAC() string {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "00:00:00:00:00:00"
	}
	// Locally administered, unicast.
	raw[0] = (raw[0] | 0x02) &^ 0x01
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", raw[0], raw[1], raw[2], raw[3], raw[4], raw[5])
}
