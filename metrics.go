package acmednschallenge

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	certExpiry = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: name,
		Name:      "cert_expiry_timestamp_seconds",
		Help:      "Certificate expiry (NotAfter) as a unix timestamp, per domain.",
	}, []string{"domain"})

	obtainCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: name,
		Name:      "obtain_total",
		Help:      "Counter of certificate obtain/renew attempts by result.",
	}, []string{"domain", "result"})

	challengeResponses = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: name,
		Name:      "challenge_responses_total",
		Help:      "Counter of ACME DNS-01 TXT challenge responses served.",
	}, []string{"server"})

	clusterPeers = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: name,
		Name:      "cluster_peers",
		Help:      "Number of cluster peers resolved on the last discovery.",
	})

	clusterIssuing = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: name,
		Name:      "cluster_issuing",
		Help:      "Whether this node is currently issuing/renewing a certificate (1) or not (0).",
	})

	clusterPushFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: name,
		Name:      "cluster_push_failures_total",
		Help:      "Counter of failed challenge pushes to cluster peers.",
	})
)

func recordObtain(domain, result string, err error) {
	if err != nil {
		result = "failed"
	}
	obtainCount.WithLabelValues(domain, result).Inc()
}
