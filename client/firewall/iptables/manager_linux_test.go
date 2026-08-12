//go:build privileged

package iptables

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

var ifaceMock = &iFaceMock{
	NameFunc: func() string {
		return "wg-test"
	},
	AddressFunc: func() wgaddr.Address {
		return wgaddr.Address{
			IP:      netip.MustParseAddr("10.20.0.1"),
			Network: netip.MustParsePrefix("10.20.0.0/24"),
		}
	},
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMock struct {
	NameFunc    func() string
	AddressFunc func() wgaddr.Address
}

func (i *iFaceMock) Name() string {
	if i.NameFunc != nil {
		return i.NameFunc()
	}
	panic("NameFunc is not set")
}

func (i *iFaceMock) Address() wgaddr.Address {
	if i.AddressFunc != nil {
		return i.AddressFunc()
	}
	panic("AddressFunc is not set")
}

func TestIptablesManager(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	// just check on the local interface
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	time.Sleep(time.Second)

	defer func() {
		err := manager.Close(nil)
		require.NoError(t, err, "clear the manager state")

		time.Sleep(time.Second)
	}()

	var rule2 []fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{
			IsRange: true,
			Values:  []uint16{8043, 8046},
		}
		rule2, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", port, nil, fw.ActionAccept, "")
		require.NoError(t, err, "failed to add rule")

		for _, r := range rule2 {
			rr := r.(*Rule)
			checkRuleSpecs(t, ipv4Client, rr.chain, true, rr.specs...)
		}
	})

	t.Run("delete second rule", func(t *testing.T) {
		for _, r := range rule2 {
			err := manager.DeletePeerRule(r)
			require.NoError(t, err, "failed to delete rule")
		}

		require.Empty(t, manager.aclMgr.ipsetStore.ipsets, "rulesets index after removed second rule must be empty")
	})

	t.Run("reset check", func(t *testing.T) {
		// add second rule
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{Values: []uint16{5353}}
		_, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "udp", nil, port, fw.ActionAccept, "")
		require.NoError(t, err, "failed to add rule")

		err = manager.Close(nil)
		require.NoError(t, err, "failed to reset")

		ok, err := ipv4Client.ChainExists("filter", chainNameInputRules)
		require.NoError(t, err, "failed check chain exists")

		if ok {
			require.NoErrorf(t, err, "chain '%v' still exists after Close", chainNameInputRules)
		}
	})
}

func TestIptablesManagerDenyRules(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		err := manager.Close(nil)
		require.NoError(t, err)
	}()

	t.Run("add deny rule", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{Values: []uint16{22}}

		rule, err := manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionDrop, "deny-ssh")
		require.NoError(t, err, "failed to add deny rule")
		require.NotEmpty(t, rule, "deny rule should not be empty")

		// Verify the rule was added by checking iptables
		for _, r := range rule {
			rr := r.(*Rule)
			checkRuleSpecs(t, ipv4Client, rr.chain, true, rr.specs...)
		}
	})

	t.Run("deny rule precedence test", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.4")
		port := &fw.Port{Values: []uint16{80}}

		// Add accept rule first
		_, err := manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionAccept, "accept-http")
		require.NoError(t, err, "failed to add accept rule")

		// Add deny rule second for same IP/port - this should take precedence
		_, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionDrop, "deny-http")
		require.NoError(t, err, "failed to add deny rule")

		// Inspect the actual iptables rules to verify deny rule comes before accept rule
		rules, err := ipv4Client.List("filter", chainNameInputRules)
		require.NoError(t, err, "failed to list iptables rules")

		// Debug: print all rules
		t.Logf("All iptables rules in chain %s:", chainNameInputRules)
		for i, rule := range rules {
			t.Logf("  [%d] %s", i, rule)
		}

		var denyRuleIndex, acceptRuleIndex = -1, -1
		for i, rule := range rules {
			if strings.Contains(rule, "DROP") {
				t.Logf("Found DROP rule at index %d: %s", i, rule)
				if strings.Contains(rule, "deny-http") && strings.Contains(rule, "80") {
					denyRuleIndex = i
				}
			}
			if strings.Contains(rule, "ACCEPT") {
				t.Logf("Found ACCEPT rule at index %d: %s", i, rule)
				if strings.Contains(rule, "accept-http") && strings.Contains(rule, "80") {
					acceptRuleIndex = i
				}
			}
		}

		require.NotEqual(t, -1, denyRuleIndex, "deny rule should exist in iptables")
		require.NotEqual(t, -1, acceptRuleIndex, "accept rule should exist in iptables")
		require.Less(t, denyRuleIndex, acceptRuleIndex,
			"deny rule should come before accept rule in iptables chain (deny at index %d, accept at index %d)",
			denyRuleIndex, acceptRuleIndex)
	})
}

func TestIptablesManagerIPSet(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "wg-test"
		},
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
			}
		},
	}

	// just check on the local interface
	manager, err := Create(mock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	time.Sleep(time.Second)

	defer func() {
		err := manager.Close(nil)
		require.NoError(t, err, "clear the manager state")

		time.Sleep(time.Second)
	}()

	var rule2 []fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{
			Values: []uint16{443},
		}
		rule2, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", port, nil, fw.ActionAccept, "default")
		for _, r := range rule2 {
			require.NoError(t, err, "failed to add rule")
			require.Equal(t, r.(*Rule).ipsetName, "default-sport", "ipset name must be set")
			require.Equal(t, r.(*Rule).ip, "10.20.0.3", "ipset IP must be set")
		}
	})

	t.Run("delete second rule", func(t *testing.T) {
		for _, r := range rule2 {
			err := manager.DeletePeerRule(r)
			require.NoError(t, err, "failed to delete rule")

			require.Empty(t, manager.aclMgr.ipsetStore.ipsets, "rulesets index after removed second rule must be empty")
		}
	})

	t.Run("reset check", func(t *testing.T) {
		err = manager.Close(nil)
		require.NoError(t, err, "failed to reset")
	})
}

func checkRuleSpecs(t *testing.T, ipv4Client *iptables.IPTables, chainName string, mustExists bool, rulespec ...string) {
	t.Helper()
	exists, err := ipv4Client.Exists("filter", chainName, rulespec...)
	require.NoError(t, err, "failed to check rule")
	require.Falsef(t, !exists && mustExists, "rule '%v' does not exist", rulespec)
	require.Falsef(t, exists && !mustExists, "rule '%v' exist", rulespec)
}

func TestIptablesCreatePerformance(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "wg-test"
		},
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
			}
		},
	}

	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			manager, err := Create(mock, iface.DefaultMTU)
			require.NoError(t, err)
			require.NoError(t, manager.Init(nil))
			time.Sleep(time.Second)

			defer func() {
				err := manager.Close(nil)
				require.NoError(t, err, "clear the manager state")

				time.Sleep(time.Second)
			}()

			require.NoError(t, err)

			ip := netip.MustParseAddr("10.20.0.100")
			start := time.Now()
			for i := 0; i < testMax; i++ {
				port := &fw.Port{Values: []uint16{uint16(1000 + i)}}
				_, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionAccept, "")

				require.NoError(t, err, "failed to add rule")
			}
			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}

// newACLTestManager returns a started manager. Create()/Init() is used so the
// router-owned chains (chainRTFWDIN/OUT) exist before the ACL manager's
// createDefaultChains() references them.
func newACLTestManager(t *testing.T) *Manager {
	t.Helper()

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	return manager
}

// TestIptablesACLUsesIPSetOnHealthyKernel guards the default: on a kernel that
// does have ipset, rules must keep matching a set. A regression that reported
// ipset as unusable would silently move every Linux client to per-IP rules.
func TestIptablesACLUsesIPSetOnHealthyKernel(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	manager := newACLTestManager(t)

	ip := netip.MustParseAddr("10.20.0.42")
	port := &fw.Port{Values: []uint16{22}}

	rules, err := manager.aclMgr.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionAccept, "nb0000001")
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	rule := rules[0].(*Rule)
	require.Equal(t, "nb0000001-dport", rule.ipsetName, "healthy kernel must use an ipset")
	require.Contains(t, rule.specs, "--match-set")
	require.True(t, manager.ipsetSupport.supported(), "ipset must not be latched off on a healthy kernel")

	checkRuleSpecs(t, ipv4Client, rule.chain, true, rule.specs...)
}

// TestIptablesACLFallsBackWhenIPSetUnusable drives the real failure path: an
// oversized set name is rejected by the kernel, which stands in for a kernel
// without ip_set_hash_net or xt_set. The rule must still land in the chain,
// matching the IP directly, and the capability must latch off so later rules skip
// ipset. Before the fallback existed, the rule was dropped and the catch-all DROP
// silently blocked traffic the policy permits.
func TestIptablesACLFallsBackWhenIPSetUnusable(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	manager := newACLTestManager(t)

	// ipset names are limited to 31 characters, so creating this set fails.
	unusableName := strings.Repeat("a", 40)

	ip := netip.MustParseAddr("10.20.0.42")
	port := &fw.Port{Values: []uint16{22}}

	rules, err := manager.aclMgr.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionAccept, unusableName)
	require.NoError(t, err, "AddPeerFiltering must succeed by falling back")
	require.NotEmpty(t, rules)

	rule := rules[0].(*Rule)
	require.Empty(t, rule.ipsetName, "fallback rule must not reference an ipset")
	require.Contains(t, strings.Join(rule.specs, " "), "-s 10.20.0.42", "fallback rule must match the source IP")
	require.NotContains(t, strings.Join(rule.specs, " "), "--match-set")

	// The rule must actually be present, not silently missing.
	checkRuleSpecs(t, ipv4Client, rule.chain, true, rule.specs...)

	require.False(t, manager.ipsetSupport.supported(), "failure must latch ipset off")

	// A subsequent rule with a perfectly valid set name now skips ipset too.
	next, err := manager.aclMgr.AddPeerFiltering(nil, netip.MustParseAddr("10.20.0.43").AsSlice(), "tcp", nil, port, fw.ActionAccept, "nb0000001")
	require.NoError(t, err)
	require.NotEmpty(t, next)
	require.Empty(t, next[0].(*Rule).ipsetName, "later rules must skip ipset once latched")
}

// TestIptablesACLLeavesNoIPSetAfterFallback verifies the set created before the
// failure is destroyed, so a later rule does not find a half-built set and assume
// ipset works.
func TestIptablesACLLeavesNoIPSetAfterFallback(t *testing.T) {
	manager := newACLTestManager(t)

	port := &fw.Port{Values: []uint16{22}}
	ip := netip.MustParseAddr("10.20.0.42")

	_, err := manager.aclMgr.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionAccept, strings.Repeat("a", 40))
	require.NoError(t, err)

	_, exists := manager.aclMgr.ipsetStore.ipset(strings.Repeat("a", 40) + "-dport")
	require.False(t, exists, "unusable set must not stay in the store")
}
