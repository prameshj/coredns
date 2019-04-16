package autopath

import (
	"encoding/hex"
	"fmt"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/mholt/caddy"
	"github.com/miekg/dns"

	"strings"
)

var log = clog.NewWithPlugin("autopath")

func init() {
	caddy.RegisterPlugin("autopath", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})

}

func setup(c *caddy.Controller) error {
	ap, mw, err := autoPathParse(c)
	if err != nil {
		return plugin.Error("autopath", err)
	}

	c.OnStartup(func() error {
		metrics.MustRegister(c, autoPathCount)
		return nil
	})

	// Do this in OnStartup, so all plugin has been initialized.
	c.OnStartup(func() error {
		if mw == "fromedns" {
			ap.searchFunc = fromEdns
		}
		m := dnsserver.GetConfig(c).Handler(mw)
		if m == nil {
			return nil
		}
		if x, ok := m.(AutoPather); ok {
			ap.searchFunc = x.AutoPath
		} else {
			return plugin.Error("autopath", fmt.Errorf("%s does not implement the AutoPather interface", mw))
		}
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ap.Next = next
		return ap
	})

	return nil
}

func fromEdns(state request.Request) []string {
	opt := state.Req.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if o.Option() == 0xfffe {
			// option string is of the form "65534:0xa4563.."
			decoded, err := hex.DecodeString(strings.TrimPrefix(o.String(), "65534:0x"))
			if err != nil {
				log.Errorf("Failed to decode searchpath %s - %s", o.String(), err)
				return nil
			}
			log.Warningf("Searchpath is %s", decoded)
			return strings.Split(string(decoded), ",")
		}
	}
	return nil
}

func autoPathParse(c *caddy.Controller) (*AutoPath, string, error) {
	ap := &AutoPath{}
	mw := ""

	for c.Next() {
		zoneAndresolv := c.RemainingArgs()
		if len(zoneAndresolv) < 1 {
			return ap, "", fmt.Errorf("no resolv-conf specified")
		}
		resolv := zoneAndresolv[len(zoneAndresolv)-1]
		if resolv[0] == '@' {
			mw = resolv[1:]
		} else {
			// assume file on disk
			rc, err := dns.ClientConfigFromFile(resolv)
			if err != nil {
				return ap, "", fmt.Errorf("failed to parse %q: %v", resolv, err)
			}
			ap.search = rc.Search
			plugin.Zones(ap.search).Normalize()
			ap.search = append(ap.search, "") // sentinel value as demanded.
		}
		ap.Zones = zoneAndresolv[:len(zoneAndresolv)-1]
		if len(ap.Zones) == 0 {
			ap.Zones = make([]string, len(c.ServerBlockKeys))
			copy(ap.Zones, c.ServerBlockKeys)
		}
		for i, str := range ap.Zones {
			ap.Zones[i] = plugin.Host(str).Normalize()
		}
	}
	return ap, mw, nil
}
