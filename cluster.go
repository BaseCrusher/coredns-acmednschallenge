package acmednschallenge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/acmednschallenge/config"
)

const (
	clusterAPITimeout = 2 * time.Second
	clusterTick       = 5 * time.Second
	clusterSettle     = clusterTick + 2*time.Second
)

type role int

const (
	roleFollower role = iota
	roleLeaderPending
	roleLeaderActive
)

type statusResponse struct {
	Leader     bool                `json:"leader"`
	Challenges map[string][]string `json:"challenges"`
}

type cluster struct {
	ac      *acmeChallenge
	service string
	port    int

	resolvePeers   func() ([]string, error)
	isLocal        func(ip string) bool
	getStatus      func(peer string) (statusResponse, bool)
	postChallenges func(peer string, records map[string][]string)
	tick           time.Duration
	settle         time.Duration

	httpClient *http.Client

	mu           sync.Mutex
	role         role
	pendingSince time.Time
	leaderCancel context.CancelFunc
	otherIssuing bool
}

func newCluster(ac *acmeChallenge, cfg *config.ClusterConfig) *cluster {
	c := &cluster{
		ac:         ac,
		service:    cfg.PeerService,
		port:       cfg.APIPort,
		tick:       clusterTick,
		settle:     clusterSettle,
		httpClient: &http.Client{Timeout: clusterAPITimeout},
		role:       roleFollower,
	}
	c.resolvePeers = func() ([]string, error) { return net.LookupHost(c.service) }
	c.isLocal = isLocalIP
	if cfg.OwnIP != "" {
		own := cfg.OwnIP
		c.isLocal = func(ip string) bool { return ip == own }
	}
	c.getStatus = c.httpGetStatus
	c.postChallenges = c.httpPostChallenges
	return c
}

func (c *cluster) run() {
	c.ac.challenges.setOnChange(func() {
		if c.currentRole() == roleLeaderActive {
			c.pushToPeers()
		}
	})

	go c.serveAPI()

	c.reconcile()
	for {
		time.Sleep(c.tick + jitter())
		c.reconcile()
	}
}

func jitter() time.Duration {
	return time.Duration(50+rand.Intn(451)) * time.Millisecond
}

func (c *cluster) serveAPI() {
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/status", c.handleStatus)
	mux.HandleFunc("/acme/challenges", c.handleChallenges)
	addr := fmt.Sprintf(":%d", c.port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Infof("cluster API listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Errorf("cluster API server stopped: %v", err)
	}
}

func (c *cluster) handleStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.localStatus())
}

func (c *cluster) handleChallenges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var records map[string][]string
	if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c.ac.challenges.replace(records)
	w.WriteHeader(http.StatusNoContent)
}

func (c *cluster) localStatus() statusResponse {
	return statusResponse{
		Leader:     c.isLeaderClaimant(),
		Challenges: c.ac.challenges.snapshot(),
	}
}

func (c *cluster) httpGetStatus(peer string) (statusResponse, bool) {
	url := fmt.Sprintf("http://%s:%d/acme/status", peer, c.port)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return statusResponse{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusResponse{}, false
	}
	var st statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return statusResponse{}, false
	}
	return st, true
}

func (c *cluster) httpPostChallenges(peer string, records map[string][]string) {
	body, err := json.Marshal(records)
	if err != nil {
		return
	}
	url := fmt.Sprintf("http://%s:%d/acme/challenges", peer, c.port)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Warningf("cluster: push to %s failed: %v", peer, err)
		return
	}
	resp.Body.Close()
}

func (c *cluster) pushToPeers() {
	snap := c.ac.challenges.snapshot()
	peers, err := c.resolvePeers()
	if err != nil {
		log.Errorf("cluster: resolve peers for push: %v", err)
		return
	}
	for _, p := range peers {
		if c.isLocal(p) {
			continue
		}
		go c.postChallenges(p, snap)
	}
}

func (c *cluster) reconcile() {
	peers, err := c.resolvePeers()
	if err != nil {
		log.Errorf("cluster: peer resolution failed: %v", err)
		return
	}

	myIP := ""
	for _, p := range peers {
		if c.isLocal(p) {
			myIP = p
			break
		}
	}
	if myIP == "" {
		log.Warning("cluster: could not identify own IP among resolved peers; staying put")
		return
	}

	states := map[string]statusResponse{myIP: c.localStatus()}
	alive := map[string]bool{myIP: true}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, p := range peers {
		if p == myIP {
			continue
		}
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			st, ok := c.getStatus(peer)
			mu.Lock()
			alive[peer] = ok
			if ok {
				states[peer] = st
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	var claimants, aliveIPs []string
	for ip := range alive {
		if !alive[ip] {
			continue
		}
		aliveIPs = append(aliveIPs, ip)
		if states[ip].Leader {
			claimants = append(claimants, ip)
		}
	}
	pool := claimants
	if len(pool) == 0 {
		pool = aliveIPs
	}
	leaderIP := lowestIP(pool)

	busyIncumbent := false
	for _, ip := range aliveIPs {
		if ip != myIP && states[ip].Leader && len(states[ip].Challenges) > 0 {
			busyIncumbent = true
			break
		}
	}
	c.mu.Lock()
	c.otherIssuing = busyIncumbent
	c.mu.Unlock()

	c.applyElection(myIP, leaderIP, states[leaderIP])
}

func (c *cluster) applyElection(myIP, leaderIP string, leaderStatus statusResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if leaderIP == myIP {
		switch c.role {
		case roleFollower:
			c.role = roleLeaderPending
			c.pendingSince = time.Now()
			log.Infof("cluster: claiming leadership (pending), ip=%s", myIP)
		case roleLeaderPending:
			if time.Since(c.pendingSince) >= c.settle {
				c.startLeaderLoop()
				log.Info("cluster: promoted to active leader")
			}
		case roleLeaderActive:
		}
		return
	}

	if c.role == roleLeaderActive && !c.ac.challenges.isEmpty() {
		log.Info("cluster: lower-IP leader present but challenge in flight; deferring demotion")
		return
	}
	if c.role == roleLeaderActive {
		c.stopLeaderLoop()
	}
	if c.role != roleFollower {
		log.Infof("cluster: following leader %s", leaderIP)
	}
	c.role = roleFollower
	c.ac.challenges.replace(leaderStatus.Challenges)
}

func (c *cluster) startLeaderLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	c.leaderCancel = cancel
	c.role = roleLeaderActive
	go c.ac.start(ctx)
}

func (c *cluster) stopLeaderLoop() {
	if c.leaderCancel != nil {
		c.leaderCancel()
		c.leaderCancel = nil
	}
}

func (c *cluster) currentRole() role {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.role
}

func (c *cluster) otherNodeIssuing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.otherIssuing
}

func (c *cluster) waitForSoleIssuer(ctx context.Context) bool {
	for c.otherNodeIssuing() {
		log.Info("cluster: another node is issuing; waiting before starting cert cycle")
		select {
		case <-ctx.Done():
			return false
		case <-time.After(c.tick):
		}
	}
	return true
}

func (c *cluster) isLeaderClaimant() bool {
	r := c.currentRole()
	return r == roleLeaderPending || r == roleLeaderActive
}

func isLocalIP(ip string) bool {
	target := net.ParseIP(ip)
	if target == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(target) {
			return true
		}
	}
	return false
}

func lowestIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	sorted := append([]string(nil), ips...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(sorted[i]).To16(), net.ParseIP(sorted[j]).To16()) < 0
	})
	return sorted[0]
}
