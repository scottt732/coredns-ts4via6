package tailscale

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/fall"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("ts4via6")

type MatchType int

const (
	SuffixMatch MatchType = iota
	RegexMatch
)

type DnsServer struct {
	dnsServerIpv4  net.IP
	dnsServer4via6 net.IP
}

//goland:noinspection GoNameStartsWithPackageName
type TailscaleConfigEntry struct {
	siteNumber   uint16
	matchType    MatchType
	suffix       *string
	pattern      *regexp.Regexp
	ipv4cidr     net.IPNet
	ipv4via6cidr net.IPNet
	dnsServers   []DnsServer
}

//goland:noinspection GoNameStartsWithPackageName
type TailscaleConfig struct {
	sites []TailscaleConfigEntry
}

type Tailscale struct {
	Next     plugin.Handler
	config   *TailscaleConfig
	mappings *[]TailscaleConfigEntry
	ready    bool
	mutex    sync.RWMutex
	Fall     fall.F
}

type dnsQueryResult struct {
	response  *dns.Msg
	err       error
	entry     *TailscaleConfigEntry
	dnsServer DnsServer
}

func (t *Tailscale) Name() string { return "ts4via6" }

func (t *Tailscale) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	log.Debug("Handling request")

	domain := extractDomainName(r)
	if domain == "" {
		return plugin.NextOrFailure(t.Name(), t.Next, ctx, w, r)
	}

	sites := t.findMatchingSites(domain)
	if len(sites) == 0 {
		log.Debugf("Request '%s': No matching sites.", domain)
		return plugin.NextOrFailure(t.Name(), t.Next, ctx, w, r)
	} else {
		log.Infof("Request '%s': %d matching sites", domain, len(sites))
	}

	response, err := forwardToAllServers(sites, r)
	if err != nil {
		return dns.RcodeServerFailure, err
	}

	if response != nil {
		changed := translateResponseToIPv6(response.response, response.entry.siteNumber)

		if changed {
			err = w.WriteMsg(response.response)
			if err != nil {
				return dns.RcodeServerFailure, err
			}
			return dns.RcodeSuccess, nil
		} else {
			err = w.WriteMsg(response.response)
			if err != nil {
				return dns.RcodeServerFailure, err
			}
			return dns.RcodeSuccess, nil
		}
	}

	return plugin.NextOrFailure(t.Name(), t.Next, ctx, w, r)
}

func (t *Tailscale) findMatchingSites(domain string) []*TailscaleConfigEntry {
	var matchingSites []*TailscaleConfigEntry

	for _, site := range t.config.sites {
		switch site.matchType {
		case SuffixMatch:
			if strings.HasSuffix(domain, *site.suffix) {
				matchingSites = append(matchingSites, &site)
			}
		case RegexMatch:
			if site.pattern.MatchString(domain) {
				matchingSites = append(matchingSites, &site)
			}
		}
	}

	return matchingSites
}

func (t *Tailscale) start() error {
	log.Info("Starting!")
	return nil
}

func extractDomainName(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	// Extract the domain name from the first question
	return r.Question[0].Name
}

func forwardToAllServers(sites []*TailscaleConfigEntry, r *dns.Msg) (*dnsQueryResult, error) {
	ch := make(chan dnsQueryResult, len(sites))

	for _, server := range sites {
		for _, dnsServer := range server.dnsServers {
			go forwardDNSQuery(server, dnsServer, r, ch)
		}
	}

	var firstSuccessfulResponse *dnsQueryResult
	for range sites {
		result := <-ch
		if result.err == nil && result.response != nil {
			if firstSuccessfulResponse == nil {
				firstSuccessfulResponse = &result
			}
		} else {
			log.Errorf("DNS query failed for dnsServer %s: %v", result.dnsServer.dnsServer4via6.String(), result.err)
		}
	}

	if firstSuccessfulResponse != nil {
		log.Debug("Got successful response!")
		if translateResponseToIPv6(firstSuccessfulResponse.response, firstSuccessfulResponse.entry.siteNumber) {
			log.Debugf("Translated to %s", firstSuccessfulResponse.response.String())
		}
		return firstSuccessfulResponse, nil
	}

	return nil, fmt.Errorf("all DNS queries failed")
}

func forwardDNSQuery(server *TailscaleConfigEntry, dnsServer DnsServer, r *dns.Msg, ch chan<- dnsQueryResult) {
	log.Infof("Sending to %s (%s)...", dnsServer.dnsServer4via6, dnsServer.dnsServerIpv4.String())

	client := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}

	dnsServerAddr := net.JoinHostPort(dnsServer.dnsServer4via6.String(), "53")

	response, _, err := client.Exchange(r, dnsServerAddr)
	ch <- dnsQueryResult{
		response:  response,
		err:       err,
		entry:     server,
		dnsServer: dnsServer,
	}
}

func translateResponseToIPv6(response *dns.Msg, siteNumber uint16) bool {
	changed := false

	for i, answer := range response.Answer {
		if cnameRecord, ok := answer.(*dns.CNAME); ok {
			finalIPv4s, err := net.LookupIP(cnameRecord.Target)
			if err != nil || len(finalIPv4s) == 0 {
				continue
			}

			for _, ipv4 := range finalIPv4s {
				if ipv4.To4() != nil {
					ipv6 := Ipv4To4via6(ipv4, siteNumber)

					aaaaRecord := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   cnameRecord.Hdr.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    cnameRecord.Hdr.Ttl,
						},
						AAAA: ipv6,
					}
					response.Answer[i] = aaaaRecord
					changed = true
					break
				}
			}
		} else if aRecord, ok := answer.(*dns.A); ok {
			ipv4 := aRecord.A
			ipv6 := Ipv4To4via6(ipv4, siteNumber)

			aaaaRecord := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   aRecord.Hdr.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    aRecord.Hdr.Ttl,
				},
				AAAA: ipv6,
			}
			response.Answer[i] = aaaaRecord
			changed = true
		}
	}

	return changed
}
