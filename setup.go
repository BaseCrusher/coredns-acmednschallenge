package acmednschallenge

import (
	"context"
	"errors"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/acmednschallenge/config"
)

const name = "acmednschallenge"

type registeredKey struct{}

func init() { plugin.Register(name, setup) }

func setup(c *caddy.Controller) error {
	blockIdx := c.ServerBlockIndex

	registered, _ := c.Get(registeredKey{}).(map[int]bool)
	if registered == nil {
		registered = map[int]bool{}
		c.Set(registeredKey{}, registered)
	}
	if registered[blockIdx] {
		return plugin.Error(name, errors.New("only one acmechallenge per server block is allowed"))
	}
	registered[blockIdx] = true

	cfg, err := config.ParseConfig(c)
	if err != nil {
		return plugin.Error(name, err)
	}

	ac, err := newAcmeChallenge(cfg)
	if err != nil {
		return plugin.Error(name, err)
	}

	c.OnStartup(func() error {
		if ac.cluster != nil {
			go ac.cluster.start()
		} else {
			go ac.start(context.Background())
		}
		return nil
	})

	if ac.cluster != nil {
		c.OnShutdown(func() error {
			ac.cluster.stop()
			return nil
		})
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ac.Next = next
		return ac
	})

	return nil
}
