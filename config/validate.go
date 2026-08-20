package config

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/acmednschallenge/storage"
)

// lookupGid resolves a group name to its numeric gid, or accepts a numeric gid directly.
func lookupGid(group string) (int, error) {
	if g, err := user.LookupGroup(group); err == nil {
		return strconv.Atoi(g.Gid)
	}
	if gid, err := strconv.Atoi(group); err == nil && gid > 0 {
		return gid, nil
	}
	return 0, fmt.Errorf("unknown group %q", group)
}

func parseDiskModeAndGroup(c *caddy.Controller, o *storage.Options, directive string) error {
	if c.NextArg() {
		mode, ok := parseFileMode(c.Val())
		if !ok {
			return c.Errf("%s file mode must be 600, 640 or 644 but the value is: %v", directive, c.Val())
		}
		o.FileMode = mode
	}
	if c.NextArg() {
		if o.FileMode&0o070 == 0 {
			return c.Errf("%s group can only be set when the file mode grants group access (640 or 644), but the mode is %#o", directive, o.FileMode.Perm())
		}
		gid, err := lookupGid(c.Val())
		if err != nil {
			return c.Errf("%s group must be an existing group name or numeric gid: %v", directive, err)
		}
		o.GroupId = gid
	}
	return nil
}

func parseFileMode(v string) (os.FileMode, bool) {
	switch v {
	case "600":
		return os.FileMode(0600), true
	case "640":
		return os.FileMode(0640), true
	case "644":
		return os.FileMode(0644), true
	default:
		return 0, false
	}
}

func countTrue(bools ...bool) int {
	n := 0
	for _, b := range bools {
		if b {
			n++
		}
	}
	return n
}

func isSubdomainOf(san, zone string) bool {
	san = strings.TrimSuffix(strings.ToLower(san), ".")
	san = strings.TrimPrefix(san, "*.")
	zone = strings.ToLower(zone)
	return san == zone || strings.HasSuffix(san, "."+zone)
}

func isValidNameserver(ns string) bool {
	host, port, err := net.SplitHostPort(ns)
	if err != nil {
		host = ns
		port = ""
	}

	if ip := net.ParseIP(host); ip != nil {
		if port != "" {
			if _, err := net.LookupPort("udp", port); err != nil {
				return false
			}
		}
		return true
	}

	fqdnRegex := `^(?i)[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$`
	matched, _ := regexp.MatchString(fqdnRegex, host)
	return matched
}
