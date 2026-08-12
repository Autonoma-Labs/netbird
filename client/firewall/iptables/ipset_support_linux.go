package iptables

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// ipsetSupport tracks whether ipset-backed firewall rules can be installed.
//
// It starts optimistic and latches to unsupported the first time the kernel
// proves otherwise: either the hash:net set type is missing (ip_set_hash_net) or
// iptables cannot match against a set (xt_set). Callers then emit per-IP and
// per-prefix rules instead. Without the fallback, a rule referencing an unusable
// set is never installed and the catch-all DROP silently blocks traffic the
// policy permits.
//
// One instance is shared by the ACL managers and routers of both address
// families, because ipset availability is a property of the kernel rather than
// of any single table.
type ipsetSupport struct {
	mu          sync.RWMutex
	unsupported bool
}

func newIPSetSupport() *ipsetSupport {
	return &ipsetSupport{}
}

func (s *ipsetSupport) supported() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return !s.unsupported
}

// markUnsupported records that ipset cannot be used, logging the reason once.
func (s *ipsetSupport) markUnsupported(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.unsupported {
		return
	}
	s.unsupported = true

	log.Warnf("ipset is unavailable (%v); falling back to per-IP firewall rules. "+
		"Ensure the kernel provides ip_set_hash_net and xt_set; without them rule "+
		"sets are larger and slower to converge on networks with many peers", cause)
}

// ipsetUnusableError marks a failure attributable to ipset, so the caller can
// retry the same rule in its per-IP form before latching the capability off.
type ipsetUnusableError struct {
	cause error
}

func (e *ipsetUnusableError) Error() string { return e.cause.Error() }

func (e *ipsetUnusableError) Unwrap() error { return e.cause }

func ipsetUnusable(cause error) error {
	return &ipsetUnusableError{cause: cause}
}

// maybeIPSetUnusable marks an iptables failure as ipset-attributable only when the
// rule actually carried a set match, since the same call can fail for unrelated
// reasons on a rule that matches addresses directly.
func maybeIPSetUnusable(ipsetName string, err error) error {
	if ipsetName == "" {
		return err
	}

	return ipsetUnusable(err)
}
