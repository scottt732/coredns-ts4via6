package tailscale

import (
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"net"
	"regexp"
	"strconv"
)

func init() {
	caddy.RegisterPlugin("ts4via6", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	tailscale, err := createPlugin(c)
	if err != nil {
		return err
	}

	//goland:noinspection GoUnhandledErrorResult
	go tailscale.start()

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		tailscale.Next = next
		return tailscale
	})

	return nil
}

func createPlugin(c *caddy.Controller) (*Tailscale, error) {
	config := &TailscaleConfig{}

	for c.Next() {
		for c.NextBlock() {
			entry := TailscaleConfigEntry{}
			entry.matchType = SuffixMatch

			args := c.RemainingArgs()
			if len(args) < 4 {
				return nil, fmt.Errorf("not enough arguments for a valid site config")
			}

			siteNumberUint, err := strconv.ParseUint(args[0], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("error converting site number: %v", err)
			}
			entry.siteNumber = uint16(siteNumberUint)

			matchType := args[1]
			if matchType == "regex" {
				entry.matchType = RegexMatch
			} else if matchType == "suffix" {
				entry.matchType = SuffixMatch
			} else {
				return nil, fmt.Errorf("unknown matchType: %s", matchType)
			}

			pattern := args[2]
			if entry.matchType == SuffixMatch {
				entry.suffix = &pattern
			} else if entry.matchType == RegexMatch {
				entry.pattern = regexp.MustCompile(pattern)
			} else {
				return nil, fmt.Errorf("unknown matchType: %s", matchType)
			}

			_, ipv4cidr, err := net.ParseCIDR(args[3])
			if err != nil {
				return nil, fmt.Errorf("error parsing CIDR: %v", err)
			}
			entry.ipv4cidr = *ipv4cidr

			ipv4via6cidr := Ipv4CIDRTo4via6(ipv4cidr, entry.siteNumber)
			entry.ipv4via6cidr = *ipv4via6cidr

			dnsServers := args[4:]
			entry.dnsServers = make([]DnsServer, 0, len(dnsServers))

			for _, val := range dnsServers {
				ipv4DNS := net.ParseIP(val)
				if ipv4DNS == nil {
					return nil, fmt.Errorf("error parsing DNS IP: %v", val)
				}
				ipv6DNS := Ipv4To4via6(ipv4DNS, entry.siteNumber)

				dnsServer := DnsServer{
					dnsServerIpv4:  ipv4DNS,
					dnsServer4via6: ipv6DNS,
				}

				entry.dnsServers = append(entry.dnsServers, dnsServer)
			}

			ipv4cidrMask, _ := entry.ipv4cidr.Mask.Size()
			ipv4via6cidrMask, _ := entry.ipv4via6cidr.Mask.Size()

			log.Infof("siteNumber .......... %d", entry.siteNumber)
			if entry.matchType == SuffixMatch {
				log.Infof("suffix .............. %s", *entry.suffix)
			} else if entry.matchType == RegexMatch {
				log.Infof("pattern ............. %v", entry.pattern)
			}
			log.Infof("ipv4cidr ............ %s/%d", entry.ipv4cidr.IP, ipv4cidrMask)
			log.Infof("ipv4via6cidr ........ %s/%d", entry.ipv4via6cidr.IP, ipv4via6cidrMask)
			log.Infof("dnsServers ..........")
			for _, dns := range entry.dnsServers {
				log.Infof("  - ipv4 ............ %v", dns.dnsServerIpv4.String())
				log.Infof("    ipv6 ............ %v", dns.dnsServer4via6.String())
			}
			log.Info("")

			config.sites = append(config.sites, entry)
		}
	}

	return &Tailscale{config: config}, nil
}

func Ipv4To4via6(ipv4Addr net.IP, siteID uint16) net.IP {
	if ipv4Addr == nil || ipv4Addr.To4() == nil {
		return nil
	}

	prefix := []byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x0b, 0x1a}
	siteIDBytes := []byte{0x00, 0x00, byte(siteID >> 8), byte(siteID & 0xff)}

	ipv4Bytes := ipv4Addr.To4()
	ipv4Segment1 := []byte{ipv4Bytes[0], ipv4Bytes[1]}
	ipv4Segment2 := []byte{ipv4Bytes[2], ipv4Bytes[3]}

	ipv6Addr := append(append(append(prefix, siteIDBytes...), ipv4Segment1...), ipv4Segment2...)
	return ipv6Addr
}

func Ipv4CIDRTo4via6(cidr *net.IPNet, siteID uint16) *net.IPNet {
	ipv6IP := Ipv4To4via6(cidr.IP, siteID)
	if ipv6IP == nil {
		return nil
	}

	ones, _ := cidr.Mask.Size()
	ipv6PrefixLength := 128 - ones

	ipv6CIDR := &net.IPNet{
		IP:   ipv6IP,
		Mask: net.CIDRMask(ipv6PrefixLength, 128),
	}

	return ipv6CIDR
}
