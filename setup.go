package acmednschallenge

import (
	"errors"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const name = "acmednschallenge"

var registeredForBlock []int

func init() { plugin.Register(name, setup) }

func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

func setup(c *caddy.Controller) error {
	blockIdx := c.ServerBlockIndex

	if contains(registeredForBlock, blockIdx) {
		return plugin.Error(name, errors.New("only one acmechallenge per server block is allowed"))
	}

	registeredForBlock = append(registeredForBlock, c.ServerBlockIndex)

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error(name, err)
	}

	ac, err := newAcmeChallenge(cfg)
	if err != nil {
		return plugin.Error(name, err)
	}

	c.OnStartup(func() error {
		go ac.start()
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ac.Next = next
		return ac
	})

	return nil
}
