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
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var clusterLog = clog.NewWithPlugin(name + "/cluster")

const (
	clusterAPITimeout = 2 * time.Second
	clusterTick       = 5 * time.Second
)

type statusResponse struct {
	Challenges map[string][]string `json:"challenges"`
	Issuing    bool                `json:"issuing"`
	Issuer     string              `json:"issuer,omitempty"`
}

type challengeUpdate struct {
	Fqdn     string   `json:"fqdn"`
	Values   []string `json:"values"`
	Deleted  bool     `json:"deleted"`
	IssuerIP string   `json:"issuerIp,omitempty"`
}

type cluster struct {
	ac      *acmeChallenge
	service string
	port    int
	ownIP   string

	resolvePeers   func() ([]string, error)
	isLocal        func(ip string) bool
	getStatus      func(peer string) (statusResponse, bool)
	postChallenges func(peer, fqdn string, values []string, deleted bool, issuerIP string)
	tick           time.Duration
	startupDelay   time.Duration

	httpClient *http.Client

	mu          sync.Mutex
	issuing     int
	myIP        string
	knownIssuer string
}

func newCluster(ac *acmeChallenge, cfg *config.ClusterConfig) *cluster {
	c := &cluster{
		ac:           ac,
		service:      cfg.PeerService,
		port:         cfg.APIPort,
		tick:         clusterTick,
		ownIP:        cfg.OwnIP,
		startupDelay: cfg.StartupDelay,
		httpClient:   &http.Client{Timeout: clusterAPITimeout},
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
	c.ac.challenges.setOnChange(c.pushUpdate)
	go c.serveAPI()
	wait := c.startupDelay + ipJitter(c.ownIP)
	clusterLog.Infof("waiting %s before first certificate check", wait)
	time.Sleep(wait)
	go c.ac.start(context.Background())
	for {
		time.Sleep(c.tick)
		c.cleanStaleChallenges()
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
	clusterLog.Infof("cluster API listening on %s", addr)
	for {
		err := srv.ListenAndServe()
		wait := time.Second + ipJitter(c.ownIP)
		clusterLog.Errorf("cluster API server stopped: %v; restarting in %s", err, wait)
		time.Sleep(wait)
	}
}

func ipJitter(ip string) time.Duration {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return jitter()
	}
	var sum int
	for _, b := range parsed {
		sum += int(b)
	}
	return time.Duration(sum%500) * time.Millisecond
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
	var upd challengeUpdate
	if err := json.NewDecoder(r.Body).Decode(&upd); err != nil || upd.Fqdn == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if upd.IssuerIP != "" {
		c.mu.Lock()
		c.knownIssuer = upd.IssuerIP
		c.mu.Unlock()
	}
	if upd.Deleted {
		c.ac.challenges.applyDelete(upd.Fqdn)
	} else {
		c.ac.challenges.applySet(upd.Fqdn, upd.Values)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *cluster) localStatus() statusResponse {
	snap := c.ac.challenges.snapshot()
	c.mu.Lock()
	issuing := c.issuing > 0
	issuer := ""
	if issuing {
		issuer = c.myIP
	}
	c.mu.Unlock()
	return statusResponse{Challenges: snap, Issuing: issuing, Issuer: issuer}
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

func (c *cluster) httpPostChallenges(peer, fqdn string, values []string, deleted bool, issuerIP string) {
	body, err := json.Marshal(challengeUpdate{Fqdn: fqdn, Values: values, Deleted: deleted, IssuerIP: issuerIP})
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
		clusterPushFailures.Inc()
		clusterLog.Warningf("push to %s failed: %v", peer, err)
		return
	}
	resp.Body.Close()
}

func (c *cluster) pushUpdate(fqdn string, values []string, deleted bool) {
	c.mu.Lock()
	issuerIP := c.myIP
	c.mu.Unlock()
	peers, err := c.resolvePeers()
	if err != nil {
		clusterLog.Errorf("resolve peers for push: %v", err)
		return
	}
	for _, p := range peers {
		if c.isLocal(p) {
			continue
		}
		go c.postChallenges(p, fqdn, values, deleted, issuerIP)
	}
}

func (c *cluster) canIssue() bool {
	peers, err := c.resolvePeers()
	if err != nil {
		clusterLog.Errorf("peer resolution failed: %v", err)
		return false
	}
	clusterPeers.Set(float64(len(peers)))
	myIP := c.localIP(peers)
	if myIP == "" {
		clusterLog.Warningf("own IP not among addresses resolved for %q (%v); skipping certificate creation this cycle. Make sure that the coredns can reach the network. If this persists, set OWN_IP in the clusterMode directive.", c.service, peers)
		return false
	}

	clusterLog.Infof("discovered coredns peers for %q: %v; this node=%s; %s is most likely to issue (lowest IP, may change if a node joins)", c.service, peers, myIP, lowestIP(peers))

	for _, p := range peers {
		if p == myIP {
			continue
		}
		if st, ok := c.getStatus(p); ok && st.Issuing {
			clusterLog.Infof("peer %s is already issuing (as %q); skipping this cycle", p, st.Issuer)
			return false
		}
	}

	if lowestIP(peers) != myIP {
		return false
	}
	clusterLog.Infof("this node (%s) will issue/renew the cert", myIP)
	c.mu.Lock()
	c.myIP = myIP
	c.mu.Unlock()
	return true
}

func (c *cluster) beginIssue() {
	c.mu.Lock()
	c.issuing++
	c.mu.Unlock()
	clusterIssuing.Set(1)
}

func (c *cluster) endIssue() {
	c.mu.Lock()
	c.issuing--
	issuing := c.issuing
	c.mu.Unlock()
	if issuing <= 0 {
		clusterIssuing.Set(0)
	}
}

func (c *cluster) amIssuing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.issuing > 0
}

func (c *cluster) cleanStaleChallenges() {
	if c.ac.challenges.isEmpty() || c.amIssuing() {
		return
	}
	c.mu.Lock()
	issuer := c.knownIssuer
	c.mu.Unlock()
	if issuer != "" && !c.isLocal(issuer) {
		if st, ok := c.getStatus(issuer); ok && st.Issuing {
			return
		}
	}
	clusterLog.Info("issuer done or unreachable; clearing stale challenge records")
	c.ac.challenges.replace(nil)
}

func (c *cluster) localIP(peers []string) string {
	for _, p := range peers {
		if c.isLocal(p) {
			return p
		}
	}
	return ""
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
