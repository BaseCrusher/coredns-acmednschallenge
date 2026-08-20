package acmednschallenge

import (
	"context"
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
			c:     &cluster{ac: ac, tick: time.Millisecond, settle: 0, role: roleFollower},
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
		node.c.postChallenges = func(peer string, rec map[string][]string) {
			if pn := nodes[peer]; pn != nil && pn.alive {
				pn.c.ac.challenges.replace(rec)
			}
		}
		node.c.ac.challenges.setOnChange(func() {
			if node.c.currentRole() == roleLeaderActive {
				node.c.pushToPeers()
			}
		})
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

func TestClusterElection(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]

	for i := 0; i < 4; i++ {
		a.c.reconcile()
		b.c.reconcile()
	}

	if a.c.currentRole() != roleLeaderActive {
		t.Errorf("A (lowest IP) role = %v, want LEADER_ACTIVE", a.c.currentRole())
	}
	if b.c.currentRole() != roleFollower {
		t.Errorf("B role = %v, want FOLLOWER", b.c.currentRole())
	}
}

func TestClusterTwoLeadersLowestWins(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	a.c.role = roleLeaderActive
	b.c.role = roleLeaderActive

	b.c.reconcile()
	if b.c.currentRole() != roleFollower {
		t.Errorf("higher-IP B role = %v, want demoted to FOLLOWER", b.c.currentRole())
	}
	a.c.reconcile()
	if a.c.currentRole() != roleLeaderActive {
		t.Errorf("lowest-IP A role = %v, want still LEADER_ACTIVE", a.c.currentRole())
	}
}

func TestClusterNoDemotionMidChallenge(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	a.c.role = roleLeaderActive
	b.c.role = roleLeaderActive
	b.c.ac.challenges.add("_acme-challenge.x.example.com.", "token")

	b.c.reconcile()
	if b.c.currentRole() != roleLeaderActive {
		t.Errorf("B role = %v, want LEADER_ACTIVE (no demotion mid-challenge)", b.c.currentRole())
	}
}

func TestClusterFollowerMirrorsAndRemoval(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	a.c.role = roleLeaderActive
	b.c.role = roleFollower
	fqdn := "_acme-challenge.x.example.com."

	a.c.ac.challenges.replace(map[string][]string{fqdn: {"v1"}})
	b.c.reconcile()
	if v, ok := b.c.ac.challenges.get(fqdn); !ok || len(v) != 1 || v[0] != "v1" {
		t.Errorf("follower did not mirror record: got %v ok=%v", v, ok)
	}

	a.c.ac.challenges.replace(map[string][]string{})
	b.c.reconcile()
	if _, ok := b.c.ac.challenges.get(fqdn); ok {
		t.Error("follower did not mirror removal")
	}
}

func TestClusterLeaderPush(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	a.c.role = roleLeaderActive
	b.c.role = roleFollower
	fqdn := "_acme-challenge.x.example.com."

	a.c.ac.challenges.add(fqdn, "pushed")
	waitFor(t, "follower to receive pushed record", func() bool {
		_, ok := b.c.ac.challenges.get(fqdn)
		return ok
	})
}

func TestClusterWaitForSoleIssuerReleases(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	b.c.role = roleLeaderActive
	b.c.ac.challenges.add("_acme-challenge.x.example.com.", "token")

	a.c.reconcile()
	if !a.c.otherNodeIssuing() {
		t.Fatal("A should observe B issuing")
	}

	done := make(chan bool, 1)
	go func() { done <- a.c.waitForSoleIssuer(context.Background()) }()
	select {
	case <-done:
		t.Fatal("waitForSoleIssuer returned while peer still issuing")
	case <-time.After(10 * time.Millisecond):
	}

	b.c.ac.challenges.remove("_acme-challenge.x.example.com.")
	a.c.reconcile()
	if !<-done {
		t.Error("waitForSoleIssuer should return true once peer stopped issuing")
	}
}

func TestClusterWaitForSoleIssuerCancels(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	b.c.role = roleLeaderActive
	b.c.ac.challenges.add("_acme-challenge.x.example.com.", "token")
	a.c.reconcile()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- a.c.waitForSoleIssuer(ctx) }()
	cancel()
	if <-done {
		t.Error("waitForSoleIssuer should return false when ctx is cancelled")
	}
}

func TestClusterLeaderLossReElects(t *testing.T) {
	nodes := newClusterTestbed("10.0.0.1", "10.0.0.2")
	a, b := nodes["10.0.0.1"], nodes["10.0.0.2"]
	a.c.role = roleLeaderActive
	b.c.role = roleFollower
	b.c.reconcile()

	a.alive = false
	b.c.reconcile()
	b.c.reconcile()
	if b.c.currentRole() != roleLeaderActive {
		t.Errorf("B role = %v, want LEADER_ACTIVE after leader loss", b.c.currentRole())
	}
}
