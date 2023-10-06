// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tailscale.com/types/ipproto"
	"tailscale.com/util/vizerror"
)

// ProtoPortRange is used to encode "proto:port" format in an ACL IP field.
// The following formats are supported:
//
//	"*" allows all TCP, UDP and ICMP traffic on all ports.
//	"<ports>" allows all TCP, UDP and ICMP traffic on the specified ports.
//	"proto:*" allows traffic of the specified proto on all ports.
//	"proto:<port>" allows traffic of the specified proto on the specified port.
//
// Ports are either a single port number or a range of ports (e.g. "80-90").
type ProtoPortRange struct {
	// Proto is the IP protocol number.
	// If Proto is 0, it means TCP+UDP+ICMP(4+6).
	Proto int
	Ports PortRange
}

func (ppr ProtoPortRange) String() string {
	if ppr.Proto == 0 {
		if ppr.Ports == PortRangeAny {
			return "*"
		}
	}
	var buf strings.Builder
	switch p := ipproto.Proto(ppr.Proto); p {
	case
		ipproto.ICMPv4,
		ipproto.IGMP,
		ipproto.ICMPv6,
		ipproto.TCP,
		ipproto.UDP,
		ipproto.DCCP,
		ipproto.GRE,
		ipproto.SCTP:
		fmt.Fprintf(&buf, "%s:", strings.ToLower(p.String()))

	default:
		if ppr.Proto != 0 {
			fmt.Fprintf(&buf, "%d:", ppr.Proto)
		}
	}
	pr := ppr.Ports
	if pr.First == pr.Last {
		fmt.Fprintf(&buf, "%d", pr.First)
	} else if pr == PortRangeAny {
		buf.WriteByte('*')
	} else {
		fmt.Fprintf(&buf, "%d-%d", pr.First, pr.Last)
	}
	return buf.String()
}

// ParseProtoPortRanges parses a slice of IP port range fields.
func ParseProtoPortRanges(ips []string) ([]ProtoPortRange, error) {
	var out []ProtoPortRange
	for _, p := range ips {
		ppr, err := parseProtoPortRange(p)
		if err != nil {
			return nil, err
		}
		out = append(out, *ppr)
	}
	return out, nil
}

func parseProtoPortRange(ipProtoPort string) (*ProtoPortRange, error) {
	if ipProtoPort == "" {
		return nil, errors.New("empty string")
	}
	if ipProtoPort == "*" {
		return &ProtoPortRange{Ports: PortRangeAny}, nil
	}
	if !strings.Contains(ipProtoPort, ":") {
		ipProtoPort = "*:" + ipProtoPort
	}
	protoStr, ports, err := parseHostPortRange(ipProtoPort)
	if err != nil {
		return nil, err
	}
	if protoStr == "" {
		return nil, errors.New("empty protocol")
	}
	if len(ports) == 0 {
		return nil, errors.New("empty port range")
	}
	if len(ports) > 1 {
		return nil, errors.New("only one port range allowed")
	}

	ppr := &ProtoPortRange{
		Ports: ports[0],
	}
	if protoStr == "*" {
		return ppr, nil
	}
	ipProto, _, err := ipproto.ResolveProtoName(protoStr)
	if err != nil {
		return nil, err
	}

	ppr.Proto = int(ipProto)
	return ppr, nil
}

// parseHostPortRange parses hostport as HOST:PORTS where HOST is
// returned unchanged and PORTS is is either "*" or a comma-separated
// list of PORTNUM or PORTLOW-PORTHIGH ranges.
func parseHostPortRange(hostport string) (host string, ports []PortRange, err error) {
	hostport = strings.ToLower(hostport)

	// Need to find the *last* colon, because hostnames can contain
	// user, group and tag names. For example:
	//    tag:abc:1-3,10
	// means
	//    host: tag:abc
	//    ports: 1, 2, 3, 10
	colon := strings.LastIndexByte(hostport, ':')
	if colon < 0 {
		return "", nil, vizerror.New("hostport must contain a colon (\":\")")
	}
	host = hostport[:colon]
	portlist := hostport[colon+1:]

	if strings.Contains(host, ",") {
		return "", nil, vizerror.New("host cannot contain a comma (\",\")")
	}

	if portlist == "*" {
		// Special case: permit hostname:* as a port wildcard.
		ports = append(ports, PortRangeAny)
		return host, ports, nil
	}

	pl := strings.Split(portlist, ",")
	for _, pp := range pl {
		if len(pp) == 0 {
			return "", nil, vizerror.Errorf("invalid port list: %#v", portlist)
		}

		if strings.Count(pp, "-") > 1 {
			return "", nil, vizerror.Errorf("port range %#v: too many dashes(-)", pp)
		}

		firstStr, lastStr, isRange := strings.Cut(pp, "-")

		var first, last uint64
		first, err := strconv.ParseUint(firstStr, 10, 16)
		if err != nil {
			return "", nil, vizerror.Errorf("port range %#v: invalid first integer", pp)
		}

		if isRange {
			last, err = strconv.ParseUint(lastStr, 10, 16)
			if err != nil {
				return "", nil, vizerror.Errorf("port range %#v: invalid last integer", pp)
			}
		} else {
			last = first
		}

		if first == 0 {
			return "", nil, vizerror.Errorf("port range %#v: first port must be >0, or use '*' for wildcard", pp)
		}

		if first > last {
			return "", nil, vizerror.Errorf("port range %#v: first port must be >= last port", pp)
		}

		ports = append(ports, newPortRange(uint16(first), uint16(last)))
	}

	return host, ports, nil
}

func newPortRange(first, last uint16) PortRange {
	return PortRange{First: first, Last: last}
}
