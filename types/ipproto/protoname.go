// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipproto

import (
	"strconv"

	"tailscale.com/util/nocasemaps"
	"tailscale.com/util/vizerror"
)

// ipProtoByName maps from the "Keyword" name
// at https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// to its protocol number, for protocols we recognize by name.
// (All protocols are recognized by their decimal number.")
var ipProtoByName = map[string]Proto{
	"ah":        51,
	"egp":       8,
	"esp":       50,
	"gre":       47,
	"icmp":      ICMPv4,
	"igmp":      IGMP,
	"igp":       9,
	"ip-in-ip":  4, // IANA says "ipv4"; Wikipedia/popular use says "ip-in-ip"
	"ipv4":      4,
	"ipv6-icmp": ICMPv6,
	"sctp":      SCTP,
	"tcp":       TCP,
	"udp":       UDP,
}

// ResolveProtoName parses string s as a protocol name or number. If the protocol
// is supported, the Proto representation is returned, and ok is true. If the
// protocol is invalid or unsupported, a vizerror is returned. If s is empty, ok
// is false and no error is returned.
func ResolveProtoName(s string) (p Proto, ok bool, err error) {
	if s == "" {
		return 0, false, nil
	}
	if u, err := strconv.ParseUint(s, 10, 8); err == nil {
		p = Proto(u)
		if p == TSMP {
			return 0, false, vizerror.New("IP protocol 99 is reserved for use by Tailscale")
		}
		if s[0] == '0' {
			return 0, false, vizerror.Errorf("leading 0 not permitted in protocol number %q", s)
		}
		return p, true, nil
	}
	if p, ok := nocasemaps.GetOk(ipProtoByName, s); ok {
		return p, true, nil
	}
	return 0, false, vizerror.Errorf("proto name %q not known; use protocol number 0-255", s)
}
