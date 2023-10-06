// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

import (
	"encoding"
	"errors"
	"testing"

	"tailscale.com/types/ipproto"
)

var _ encoding.TextUnmarshaler = (*ProtoPortRange)(nil)

func TestProtoPortRangeParsing(t *testing.T) {
	pr := func(s, e uint16) PortRange {
		return PortRange{First: s, Last: e}
	}
	tests := []struct {
		in  string
		out ProtoPortRange
		err error
	}{
		{in: "tcp:80", out: ProtoPortRange{Proto: int(ipproto.TCP), Ports: pr(80, 80)}},
		{in: "80", out: ProtoPortRange{Ports: pr(80, 80)}},
		{in: "*", out: ProtoPortRange{Ports: PortRangeAny}},
		{in: "*:*", out: ProtoPortRange{Ports: PortRangeAny}},
		{in: "tcp:*", out: ProtoPortRange{Proto: int(ipproto.TCP), Ports: PortRangeAny}},
		{
			in:  "tcp:8080,8090",
			err: errors.New("only one port range allowed"),
		},
		{
			in:  "tcp:",
			err: errors.New(`invalid port list: ""`),
		},
		{
			in:  ":80",
			err: errors.New(`empty protocol`),
		},
		{
			in:  "",
			err: errors.New(`empty string`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			var ppr ProtoPortRange
			err := ppr.UnmarshalText([]byte(tc.in))
			if gotErr, wantErr := err != nil, tc.err != nil; gotErr != wantErr {
				t.Fatalf("got err %v; want %v", err, tc.err)
			} else if gotErr {
				if err.Error() != tc.err.Error() {
					t.Fatalf("got err %q; want %q", err, tc.err)
				}
				return
			}
			if ppr != tc.out {
				t.Fatalf("got %v; want %v", ppr, tc.out)
			}
		})
	}
}

func TestProtoPortRangeString(t *testing.T) {
	tests := []struct {
		input ProtoPortRange
		want  string
	}{
		{ProtoPortRange{}, "0"},

		// Zero protocol.
		{ProtoPortRange{Ports: PortRangeAny}, "*"},
		{ProtoPortRange{Ports: PortRange{23, 23}}, "23"},
		{ProtoPortRange{Ports: PortRange{80, 120}}, "80-120"},

		// Non-zero unnamed protocol.
		{ProtoPortRange{Proto: 100, Ports: PortRange{80, 80}}, "100:80"},
		{ProtoPortRange{Proto: 200, Ports: PortRange{101, 105}}, "200:101-105"},

		// Non-zero named protocol.
		{ProtoPortRange{Proto: 1, Ports: PortRangeAny}, "icmpv4:*"},
		{ProtoPortRange{Proto: 2, Ports: PortRangeAny}, "igmp:*"},
		{ProtoPortRange{Proto: 6, Ports: PortRange{10, 13}}, "tcp:10-13"},
		{ProtoPortRange{Proto: 17, Ports: PortRangeAny}, "udp:*"},
		{ProtoPortRange{Proto: 0x84, Ports: PortRange{999, 999}}, "sctp:999"},
		{ProtoPortRange{Proto: 0x3a, Ports: PortRangeAny}, "icmpv6:*"},
		{ProtoPortRange{Proto: 0x21, Ports: PortRangeAny}, "dccp:*"},
		{ProtoPortRange{Proto: 0x2f, Ports: PortRangeAny}, "gre:*"},
	}
	for _, tc := range tests {
		if got := tc.input.String(); got != tc.want {
			t.Errorf("String for %v: got %q, want %q", tc.input, got, tc.want)
		}
	}
}
