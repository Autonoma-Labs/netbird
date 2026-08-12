//go:build !android && privileged

package iptables

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/test"
	"github.com/netbirdio/netbird/client/iface"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/shared/management/domain"
)

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	return err4 == nil
}

func TestIptablesManager_RestoreOrCreateContainers(t *testing.T) {
	if !isIptablesSupported() {
		t.SkipNow()
	}

	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err, "failed to init iptables client")

	manager, err := newRouter(iptablesClient, ifaceMock, iface.DefaultMTU, newIPSetSupport())
	require.NoError(t, err, "should return a valid iptables manager")
	require.NoError(t, manager.init(nil))

	defer func() {
		assert.NoError(t, manager.Reset(), "shouldn't return error")
	}()

	// 1. established rule forward in
	// 2. estbalished rule forward out
	// 3. jump rule to POST nat chain
	// 4. jump rule to PRE mangle chain
	// 5. jump rule to PRE nat chain
	// 6. static outbound masquerade rule
	// 7. static return masquerade rule
	// 8. mangle prerouting mark rule
	// 9. mangle postrouting mark rule
	// 10. jump rule to MSS clamping chain
	// 11. MSS clamping rule for outbound traffic
	require.Len(t, manager.rules, 11, "should have created rules map")

	exists, err := manager.iptablesClient.Exists(tableNat, chainPOSTROUTING, "-j", chainRTNAT)
	require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainPOSTROUTING)
	require.True(t, exists, "postrouting jump rule should exist")

	exists, err = manager.iptablesClient.Exists(tableMangle, chainPREROUTING, "-j", chainRTPRE)
	require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableMangle, chainPREROUTING)
	require.True(t, exists, "prerouting jump rule should exist")

	pair := firewall.RouterPair{
		ID:          "abc",
		Source:      firewall.Network{Prefix: netip.MustParsePrefix("100.100.100.1/32")},
		Destination: firewall.Network{Prefix: netip.MustParsePrefix("100.100.100.0/24")},
		Masquerade:  true,
	}

	err = manager.AddNatRule(pair)
	require.NoError(t, err, "adding NAT rule should not return error")

	err = manager.Reset()
	require.NoError(t, err, "shouldn't return error")
}

func TestIptablesManager_AddNatRule(t *testing.T) {
	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range test.InsertRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			require.NoError(t, err, "failed to init iptables client")

			manager, err := newRouter(iptablesClient, ifaceMock, iface.DefaultMTU, newIPSetSupport())
			require.NoError(t, err, "shouldn't return error")
			require.NoError(t, manager.init(nil))

			defer func() {
				assert.NoError(t, manager.Reset(), "shouldn't return error")
			}()

			err = manager.AddNatRule(testCase.InputPair)
			require.NoError(t, err, "marking rule should be inserted")

			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair)
			markingRule := []string{
				"-i", ifaceMock.Name(),
				"-m", "conntrack",
				"--ctstate", "NEW",
				"-s", testCase.InputPair.Source.String(),
				"-d", testCase.InputPair.Destination.String(),
				"-j", "MARK", "--set-mark",
				fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasquerade),
			}

			exists, err := iptablesClient.Exists(tableMangle, chainRTPRE, markingRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableMangle, chainRTPRE)
			if testCase.InputPair.Masquerade {
				require.True(t, exists, "marking rule should be created")
				foundRule, found := manager.rules[natRuleKey]
				require.True(t, found, "marking rule should exist in the map")
				require.Equal(t, markingRule, foundRule, "stored marking rule should match")
			} else {
				require.False(t, exists, "marking rule should not be created")
				_, found := manager.rules[natRuleKey]
				require.False(t, found, "marking rule should not exist in the map")
			}

			// Check inverse rule
			inversePair := firewall.GetInversePair(testCase.InputPair)
			inverseRuleKey := firewall.GenKey(firewall.NatFormat, inversePair)
			inverseMarkingRule := []string{
				"!", "-i", ifaceMock.Name(),
				"-m", "conntrack",
				"--ctstate", "NEW",
				"-s", inversePair.Source.String(),
				"-d", inversePair.Destination.String(),
				"-j", "MARK", "--set-mark",
				fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasqueradeReturn),
			}

			exists, err = iptablesClient.Exists(tableMangle, chainRTPRE, inverseMarkingRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableMangle, chainRTPRE)
			if testCase.InputPair.Masquerade {
				require.True(t, exists, "inverse marking rule should be created")
				foundRule, found := manager.rules[inverseRuleKey]
				require.True(t, found, "inverse marking rule should exist in the map")
				require.Equal(t, inverseMarkingRule, foundRule, "stored inverse marking rule should match")
			} else {
				require.False(t, exists, "inverse marking rule should not be created")
				_, found := manager.rules[inverseRuleKey]
				require.False(t, found, "inverse marking rule should not exist in the map")
			}
		})
	}
}

func TestIptablesManager_RemoveNatRule(t *testing.T) {
	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range test.RemoveRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			iptablesClient, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)

			manager, err := newRouter(iptablesClient, ifaceMock, iface.DefaultMTU, newIPSetSupport())
			require.NoError(t, err, "shouldn't return error")
			require.NoError(t, manager.init(nil))
			defer func() {
				assert.NoError(t, manager.Reset(), "shouldn't return error")
			}()

			err = manager.AddNatRule(testCase.InputPair)
			require.NoError(t, err, "should add NAT rule without error")

			err = manager.RemoveNatRule(testCase.InputPair)
			require.NoError(t, err, "shouldn't return error")

			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair)
			markingRule := []string{
				"-i", ifaceMock.Name(),
				"-m", "conntrack",
				"--ctstate", "NEW",
				"-s", testCase.InputPair.Source.String(),
				"-d", testCase.InputPair.Destination.String(),
				"-j", "MARK", "--set-mark",
				fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasquerade),
			}

			exists, err := iptablesClient.Exists(tableMangle, chainRTPRE, markingRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableMangle, chainRTPRE)
			require.False(t, exists, "marking rule should not exist")

			_, found := manager.rules[natRuleKey]
			require.False(t, found, "marking rule should not exist in the manager map")

			// Check inverse rule removal
			inversePair := firewall.GetInversePair(testCase.InputPair)
			inverseRuleKey := firewall.GenKey(firewall.NatFormat, inversePair)
			inverseMarkingRule := []string{
				"!", "-i", ifaceMock.Name(),
				"-m", "conntrack",
				"--ctstate", "NEW",
				"-s", inversePair.Source.String(),
				"-d", inversePair.Destination.String(),
				"-j", "MARK", "--set-mark",
				fmt.Sprintf("%#x", nbnet.PreroutingFwmarkMasqueradeReturn),
			}

			exists, err = iptablesClient.Exists(tableMangle, chainRTPRE, inverseMarkingRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableMangle, chainRTPRE)
			require.False(t, exists, "inverse marking rule should not exist")

			_, found = manager.rules[inverseRuleKey]
			require.False(t, found, "inverse marking rule should not exist in the map")
		})
	}
}

func TestRouter_AddRouteFiltering(t *testing.T) {
	if !isIptablesSupported() {
		t.Skip("iptables not supported on this system")
	}

	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err, "Failed to create iptables client")

	r, err := newRouter(iptablesClient, ifaceMock, iface.DefaultMTU, newIPSetSupport())
	require.NoError(t, err, "Failed to create router manager")
	require.NoError(t, r.init(nil))

	defer func() {
		err := r.Reset()
		require.NoError(t, err, "Failed to reset router")
	}()

	tests := []struct {
		name        string
		sources     []netip.Prefix
		destination netip.Prefix
		proto       firewall.Protocol
		sPort       *firewall.Port
		dPort       *firewall.Port
		direction   firewall.RuleDirection
		action      firewall.Action
		expectSet   bool
	}{
		{
			name:        "Basic TCP rule with single source",
			sources:     []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			destination: netip.MustParsePrefix("10.0.0.0/24"),
			proto:       firewall.ProtocolTCP,
			sPort:       nil,
			dPort:       &firewall.Port{Values: []uint16{80}},
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name: "UDP rule with multiple sources",
			sources: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/16"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			destination: netip.MustParsePrefix("10.0.0.0/8"),
			proto:       firewall.ProtocolUDP,
			sPort:       &firewall.Port{Values: []uint16{1024, 2048}, IsRange: true},
			dPort:       nil,
			direction:   firewall.RuleDirectionOUT,
			action:      firewall.ActionDrop,
			expectSet:   true,
		},
		{
			name:        "All protocols rule",
			sources:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			destination: netip.MustParsePrefix("0.0.0.0/0"),
			proto:       firewall.ProtocolALL,
			sPort:       nil,
			dPort:       nil,
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "ICMP rule",
			sources:     []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			destination: netip.MustParsePrefix("10.0.0.0/8"),
			proto:       firewall.ProtocolICMP,
			sPort:       nil,
			dPort:       nil,
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "TCP rule with multiple source ports",
			sources:     []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
			destination: netip.MustParsePrefix("192.168.0.0/16"),
			proto:       firewall.ProtocolTCP,
			sPort:       &firewall.Port{Values: []uint16{80, 443, 8080}},
			dPort:       nil,
			direction:   firewall.RuleDirectionOUT,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "UDP rule with single IP and port range",
			sources:     []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")},
			destination: netip.MustParsePrefix("10.0.0.0/24"),
			proto:       firewall.ProtocolUDP,
			sPort:       nil,
			dPort:       &firewall.Port{Values: []uint16{5000, 5100}, IsRange: true},
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionDrop,
			expectSet:   false,
		},
		{
			name:        "TCP rule with source and destination ports",
			sources:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			destination: netip.MustParsePrefix("172.16.0.0/16"),
			proto:       firewall.ProtocolTCP,
			sPort:       &firewall.Port{Values: []uint16{1024, 65535}, IsRange: true},
			dPort:       &firewall.Port{Values: []uint16{22}},
			direction:   firewall.RuleDirectionOUT,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "Drop all incoming traffic",
			sources:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			destination: netip.MustParsePrefix("192.168.0.0/24"),
			proto:       firewall.ProtocolALL,
			sPort:       nil,
			dPort:       nil,
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionDrop,
			expectSet:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleKey, err := r.AddRouteFiltering(nil, tt.sources, firewall.Network{Prefix: tt.destination}, tt.proto, tt.sPort, tt.dPort, tt.action)
			require.NoError(t, err, "AddRouteFiltering failed")

			// A kernel without usable ipset splits a multi-source ACL into one
			// rule per source, so compare against whichever form is in effect.
			useIPSet := r.ipsetSupport.supported()

			// Check if the rules are in the internal map
			rules := routeRuleSpecs(t, r, ruleKey.ID())
			require.NotEmpty(t, rules, "Rule not found in internal map")

			// Log the internal rules
			t.Logf("Internal rules: %v", rules)

			// Check if the rules exist in iptables
			for _, rule := range rules {
				exists, err := iptablesClient.Exists(tableFilter, chainRTFWDIN, rule...)
				assert.NoError(t, err, "Failed to check rule existence")
				assert.True(t, exists, "Rule not found in iptables")
			}

			// Verify rule content
			params := routeFilteringRuleParams{
				Destination: firewall.Network{Prefix: tt.destination},
				Proto:       tt.proto,
				SPort:       tt.sPort,
				DPort:       tt.dPort,
				Action:      tt.action,
			}

			expectedRules, err := r.genRouteRuleSpecs(params, tt.sources, useIPSet)
			require.NoError(t, err, "Failed to generate expected rule spec")

			if tt.expectSet && useIPSet {
				setName := firewall.NewPrefixSet(tt.sources).HashedName()

				// Check if the set was created
				_, exists := r.ipsetCounter.Get(setName)
				assert.True(t, exists, "IPSet not created")
			}

			assert.Equal(t, expectedRules, rules, "Rule content mismatch")

			// Clean up
			err = r.DeleteRouteRule(ruleKey)
			require.NoError(t, err, "Failed to delete rule")
		})
	}
}

func TestFindSetNameInRule(t *testing.T) {
	r := &router{}

	testCases := []struct {
		name     string
		rule     []string
		expected []string
	}{
		{
			name: "Basic rule with two sets",
			rule: []string{
				"-A", "NETBIRD-RT-FWD-IN", "-p", "tcp", "-m", "set", "--match-set", "nb-2e5a2a05", "src",
				"-m", "set", "--match-set", "nb-349ae051", "dst", "-m", "tcp", "--dport", "8080", "-j", "ACCEPT",
			},
			expected: []string{"nb-2e5a2a05", "nb-349ae051"},
		},
		{
			name:     "No sets",
			rule:     []string{"-A", "NETBIRD-RT-FWD-IN", "-p", "tcp", "-j", "ACCEPT"},
			expected: []string{},
		},
		{
			name: "Multiple sets with different positions",
			rule: []string{
				"-m", "set", "--match-set", "set1", "src", "-p", "tcp",
				"-m", "set", "--match-set", "set-abc123", "dst", "-j", "ACCEPT",
			},
			expected: []string{"set1", "set-abc123"},
		},
		{
			name:     "Boundary case - sequence appears at end",
			rule:     []string{"-p", "tcp", "-m", "set", "--match-set", "final-set"},
			expected: []string{"final-set"},
		},
		{
			name:     "Incomplete pattern - missing set name",
			rule:     []string{"-p", "tcp", "-m", "set", "--match-set"},
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := r.findSets(tc.rule)

			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d sets, got %d. Sets found: %v", len(tc.expected), len(result), result)
				return
			}

			for i, set := range result {
				if set != tc.expected[i] {
					t.Errorf("Expected set %q at position %d, got %q", tc.expected[i], i, set)
				}
			}
		})
	}
}

// TestRouter_AddRouteFilteringIPSetFallback covers a kernel that cannot use ipset:
// a multi-source route ACL must become one rule per source prefix, all present in
// the chain, and deleting the ACL must remove every one of them. Without the
// fallback the rule was never installed and the interface-wide DROP in FORWARD
// silently dropped routed traffic.
func TestRouter_AddRouteFilteringIPSetFallback(t *testing.T) {
	if !isIptablesSupported() {
		t.Skip("iptables not supported on this system")
	}

	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	support := newIPSetSupport()
	support.markUnsupported(errors.New("test: pretend the kernel has no ipset"))

	r, err := newRouter(iptablesClient, ifaceMock, iface.DefaultMTU, support)
	require.NoError(t, err)
	require.NoError(t, r.init(nil))
	t.Cleanup(func() {
		require.NoError(t, r.Reset())
	})

	sources := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/16"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	destination := firewall.Network{Prefix: netip.MustParsePrefix("10.0.0.0/8")}

	rule, err := r.AddRouteFiltering(nil, sources, destination, firewall.ProtocolTCP, nil,
		&firewall.Port{Values: []uint16{443}}, firewall.ActionAccept)
	require.NoError(t, err, "route ACL must install without ipset")

	specs := routeRuleSpecs(t, r, rule.ID())
	require.Len(t, specs, len(sources), "each source prefix needs its own rule")

	for i, spec := range specs {
		joined := strings.Join(spec, " ")
		require.Contains(t, joined, "-s "+sources[i].String(), "rule must match the source prefix directly")
		require.NotContains(t, joined, matchSet, "fallback rule must not reference a set")

		exists, err := iptablesClient.Exists(tableFilter, chainRTFWDIN, spec...)
		require.NoError(t, err)
		require.True(t, exists, "rule %d must be present in %s", i, chainRTFWDIN)
	}

	require.NoError(t, r.DeleteRouteRule(rule))

	for i, spec := range specs {
		exists, err := iptablesClient.Exists(tableFilter, chainRTFWDIN, spec...)
		require.NoError(t, err)
		require.False(t, exists, "rule %d must be removed", i)
	}
	require.Empty(t, routeRuleSpecs(t, r, rule.ID()), "no rule may be left recorded")
}

// TestRouter_DestinationSetRequiresIPSet documents that a dynamic (domain)
// destination cannot be expressed without ipset: its prefixes are only known
// after DNS resolution, so there is nothing to expand into per-prefix rules. The
// call must report that rather than install a broader rule than the policy allows.
func TestRouter_DestinationSetRequiresIPSet(t *testing.T) {
	if !isIptablesSupported() {
		t.Skip("iptables not supported on this system")
	}

	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	support := newIPSetSupport()
	support.markUnsupported(errors.New("test: pretend the kernel has no ipset"))

	r, err := newRouter(iptablesClient, ifaceMock, iface.DefaultMTU, support)
	require.NoError(t, err)
	require.NoError(t, r.init(nil))
	t.Cleanup(func() {
		require.NoError(t, r.Reset())
	})

	destination := firewall.Network{Set: firewall.NewDomainSet(domain.List{"example.com"})}

	_, err = r.AddRouteFiltering(nil, []netip.Prefix{netip.MustParsePrefix("172.16.0.0/16")},
		destination, firewall.ProtocolALL, nil, nil, firewall.ActionAccept)
	require.Error(t, err, "a domain destination is not expressible without ipset")
	require.ErrorContains(t, err, "requires ipset")
}

// routeRuleSpecs collects the rules recorded for one route ACL, which is more than
// one when the ipset fallback splits it per source prefix.
func routeRuleSpecs(t *testing.T, r *router, ruleKey string) [][]string {
	t.Helper()

	var specs [][]string
	for i := 0; ; i++ {
		spec, exists := r.rules[routeRuleKey(ruleKey, i)]
		if !exists {
			return specs
		}
		specs = append(specs, spec)
	}
}
