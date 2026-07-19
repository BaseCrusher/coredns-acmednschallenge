package config

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/acmednschallenge/storage"
)

func parseVaultOptions(c *caddy.Controller, o *storage.Options) error {
	args := c.RemainingArgs()
	if len(args) < 2 {
		return c.Err("vault storage requires '<mount> <pathPrefix> [token | kubernetes <role>]'")
	}
	o.Type = "vault"
	o.VaultMount = args[0]
	o.VaultPrefix = args[1]
	o.VaultAuth = "token"
	o.VaultRole = ""

	switch rest := args[2:]; {
	case len(rest) == 0:
	case rest[0] == "token":
		if len(rest) != 1 {
			return c.Err("vault 'token' auth takes no extra arguments")
		}
	case rest[0] == "kubernetes":
		if len(rest) != 2 {
			return c.Err("vault 'kubernetes' auth requires a role: kubernetes <role>")
		}
		o.VaultAuth = "kubernetes"
		o.VaultRole = rest[1]
	default:
		return c.Errf("unknown vault auth method '%s', supported: token, kubernetes", rest[0])
	}
	return nil
}
