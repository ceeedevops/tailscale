// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appctype

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
)

func TestGolden(t *testing.T) {
	golden := `{
		"dnat": [{
			"addrs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
			"to": ["example.org"],
			"ip": ["*"]
		}],
		"sniProxy": [{
		  "addrs": ["::"],
		  "ip": ["tcp:443"],
		  "allowedDomains": ["*"]
		}],
		"advertiseRoutes": true
	  }`

	wantDNAT := []DNATConfig{{
		Addrs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		To:    []string{"example.org"},
		IP:    []tailcfg.ProtoPortRange{{Proto: 0, Ports: tailcfg.PortRange{First: 0, Last: 65535}}},
	}}

	wantSNI := []SNIProxyConfig{{
		Addrs:          []netip.Addr{netip.MustParseAddr("::")},
		IP:             []tailcfg.ProtoPortRange{{Proto: 6, Ports: tailcfg.PortRange{First: 443, Last: 443}}},
		AllowedDomains: []string{"*"},
	}}

	var config AppConnectorConfig
	if err := json.NewDecoder(strings.NewReader(golden)).Decode(&config); err != nil {
		t.Fatalf("failed to decode golden config: %v", err)
	}

	if !config.AdvertiseRoutes {
		t.Fatalf("expected AdvertiseRoutes to be true, got false")
	}

	assertEqual(t, "DNAT", config.DNAT, wantDNAT)
	assertEqual(t, "SNI", config.SNIProxy, wantSNI)
}

func assertEqual(t *testing.T, name string, a, b interface{}) {
	var addrComparer = cmp.Comparer(func(a, b netip.Addr) bool {
		return a.Compare(b) == 0
	})
	t.Helper()
	if diff := cmp.Diff(a, b, addrComparer); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
}
