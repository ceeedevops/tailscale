// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package appcfg contains an experimental configuration structure for
// "tailscale.com/app-connector" capmap extensions.
package appctype

import (
	"net/netip"

	"tailscale.com/tailcfg"
)

// AppConnectorConfig is the configuration structure for an application
// connection proxy service.
type AppConnectorConfig struct {
	// DNAT is a list of destination NAT configurations.
	DNAT []DNATConfig `json:",omitempty"`
	// SNIProxy is a list of SNI proxy configurations.
	SNIProxy []SNIProxyConfig `json:",omitempty"`

	// AdvertiseRoutes indicates that the node should advertise routes for each
	// of the addresses in service configuration address lists. If false, the
	// routes have already been advertised.
	AdvertiseRoutes bool
}

// DNATConfig is the configuration structure for a destination NAT service, also
// known as a "port forward" or "port proxy".
type DNATConfig struct {
	// Addrs is a list of addresses to listen on.
	Addrs []netip.Addr `json:",omitempty"`

	// To is a list of destination addresses to forward traffic to. It should
	// only contain one domain, or a list of IP addresses.
	To []string `json:",omitempty"`

	// IP is a list of IP specifications to forward. If omitted, all protocols are
	// forwarded. IP specifications are of the form "tcp/80", "udp/53", etc.
	IP []tailcfg.ProtoPortRange `json:",omitempty"`
}

// SNIPRoxyConfig is the configuration structure for an SNI proxy service,
// forwarding TLS connections based on the hostname field in SNI.
type SNIProxyConfig struct {
	// Addrs is a list of addresses to listen on.
	Addrs []netip.Addr `json:",omitempty"`

	// IP is a list of IP specifications to forward. If omitted, all protocols are
	// forwarded. IP specifications are of the form "tcp/80", "udp/53", etc.
	IP []tailcfg.ProtoPortRange `json:",omitempty"`

	// AllowedDomains is a list of domains that are allowed to be proxied. If
	// the domain starts with a `.` that means any subdomain of the suffix.
	AllowedDomains []string `json:",omitempty"`
}
