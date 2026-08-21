package acmednschallenge

import (
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/acmednschallenge/config"
	"github.com/go-acme/lego/v4/certificate"
)

type testNode struct {
	ip    string
	c     *cluster
	alive bool
}

func newClusterTestbed(ips ...string) map[string]*testNode {
	nodes := map[string]*testNode{}
	for _, ip := range ips {
		ac := &acmeChallenge{
			config:     &config.ACMEChallengeConfig{ManagedDomains: map[string][]string{}, CertValidationInterval: time.Hour},
			challenges: newChallengeStore(),
			storage:    &fakeStorage{},
		}
		ac.obtainOrRenew = func(string) (bool, *certificate.Resource, error) { return false, nil, nil }
		nodes[ip] = &testNode{
			ip:    ip,
			alive: true,
			c:     &cluster{ac: ac, tick: time.Millisecond},
		}
	}

	for ip, n := range nodes {
		self, node := ip, n
		node.c.resolvePeers = func() ([]string, error) { return ips, nil }
		node.c.isLocal = func(x string) bool { return x == self }
		node.c.getStatus = func(peer string) (statusResponse, bool) {
			pn := nodes[peer]
			if pn == nil || !pn.alive {
				return statusResponse{}, false
			}
			return pn.c.localStatus(), true
		}
		node.c.postChallenges = func(peer, fqdn string, values []string, deleted bool, issuerIP string) {
			if pn := nodes[peer]; pn != nil && pn.alive {
				if issuerIP != "" {
					pn.c.mu.Lock()
					pn.c.knownIssuer = issuerIP
					pn.c.mu.Unlock()
				}
				if deleted {
					pn.c.ac.challenges.applyDelete(fqdn)
				} else {
					pn.c.ac.challenges.applySet(fqdn, values)
				}
			}
		}
		node.c.ac.challenges.setOnChange(node.c.pushUpdate)
	}
	return nodes
}

func waitFor(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting: %s", msg)
}

func TestCanIssueOnlyLowestIP(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]

	if !a.c.canIssue() {
		t.Error("A (lowest IP) canIssue = false, want true")
	}
	if b.c.canIssue() {
		t.Error("B (higher IP) canIssue = true, want false")
	}
}

func TestCanIssueBlockedByPeerIssuing(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]

	b.c.beginIssue()
	if a.c.canIssue() {
		t.Error("A canIssue = true while peer B is issuing, want false")
	}
}

func TestCanIssueNewLowerIPDefersToActiveIssuer(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.5", "10.0.0.8")
	nodes["10.0.0.5"].c.beginIssue()

	all := []string{"10.0.0.1", "10.0.0.5", "10.0.0.8"}
	newcomer := &cluster{
		resolvePeers: func() ([]string, error) { return all, nil },
		isLocal:      func(x string) bool { return x == "10.0.0.1" },
		getStatus: func(peer string) (statusResponse, bool) {
			if pn := nodes[peer]; pn != nil {
				return pn.c.localStatus(), true
			}
			return statusResponse{}, false
		},
	}
	if newcomer.canIssue() {
		t.Error("newcomer with lowest IP issued while a peer was already issuing, want defer")
	}
}

func TestCanIssueOwnIPMissing(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1")
	a := nodes["10.0.0.1"]
	a.c.resolvePeers = func() ([]string, error) { return []string{"10.9.9.9"}, nil }
	if a.c.canIssue() {
		t.Error("canIssue = true when own IP absent from peers, want false")
	}
}

func TestCleanStaleChallengesClearsWhenIssuerGone(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	fqdn := "_acme-challenge.x.example.com."

	a.c.beginIssue()
	a.c.myIP = "10.0.0.1"
	a.c.ac.challenges.add(fqdn, "v1")
	waitFor(t, "follower to receive issuer push", func() bool {
		_, ok := b.c.ac.challenges.get(fqdn)
		return ok
	})
	a.alive = false

	b.c.cleanStaleChallenges()
	if _, ok := b.c.ac.challenges.get(fqdn); ok {
		t.Error("follower did not clear stale record after issuer went away")
	}
}

func TestCleanStaleChallengesKeepsWhileIssuerActive(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	fqdn := "_acme-challenge.x.example.com."

	a.c.beginIssue()
	a.c.myIP = "10.0.0.1"
	a.c.ac.challenges.add(fqdn, "v1")
	waitFor(t, "follower to receive issuer push", func() bool {
		_, ok := b.c.ac.challenges.get(fqdn)
		return ok
	})

	b.c.cleanStaleChallenges()
	if _, ok := b.c.ac.challenges.get(fqdn); !ok {
		t.Error("follower cleared record while issuer still active")
	}
}

func TestCleanStaleChallengesIssuerKeepsOwn(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a := nodes["10.0.0.1"]
	fqdn := "_acme-challenge.x.example.com."

	a.c.beginIssue()
	a.c.ac.challenges.replace(map[string][]string{fqdn: {"v1"}})

	a.c.cleanStaleChallenges()
	if _, ok := a.c.ac.challenges.get(fqdn); !ok {
		t.Error("issuer cleared its own in-flight record")
	}
}

func TestClusterPush(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	fqdn := "_acme-challenge.x.example.com."

	a.c.ac.challenges.add(fqdn, "pushed")
	waitFor(t, "follower to receive pushed record", func() bool {
		_, ok := b.c.ac.challenges.get(fqdn)
		return ok
	})
}

func TestClusterPushMultipleDomainsMerge(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	fqdnA := "_acme-challenge.a.example.com."
	fqdnB := "_acme-challenge.b.example.com."

	a.c.ac.challenges.add(fqdnA, "va")
	a.c.ac.challenges.add(fqdnB, "vb")

	waitFor(t, "follower to receive both records", func() bool {
		_, okA := b.c.ac.challenges.get(fqdnA)
		_, okB := b.c.ac.challenges.get(fqdnB)
		return okA && okB
	})
}

func TestConcurrentIssuersBothDomainsPublished(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	fqdnA := "_acme-challenge.a.example.com."
	fqdnB := "_acme-challenge.b.example.com."

	b.c.ac.challenges.add(fqdnB, "vb")
	a.c.ac.challenges.add(fqdnA, "va")

	for name, node := range map[string]*testNode{"A": a, "B": b} {
		n := node
		waitFor(t, "node "+name+" to publish both TXT records", func() bool {
			_, okA := n.c.ac.challenges.get(fqdnA)
			_, okB := n.c.ac.challenges.get(fqdnB)
			return okA && okB
		})
	}
}
