// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package trust

import (
	"net/netip"
	"strings"
)

// isLoopbackHost reports whether a host names the local machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}

	return addr.IsLoopback()
}

// isInternalHost reports whether a host names an address that is not routable on
// the public internet.
//
// The verifier only ever fetches published European documents, so a location
// resolving inwards is refused rather than followed: it would turn a document
// into a way of probing the network the verifier runs on.
func isInternalHost(host string) bool {
	host = strings.Trim(host, "[]")

	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		// A name is resolved by the transport; the literal forms are what can be
		// judged here.
		return false
	}

	return isInternalAddr(addr)
}

// isInternalAddr reports whether an address is outside the public internet.
func isInternalAddr(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	switch {
	case addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsUnspecified():
		return true
	}

	// Shared address space for carrier-grade translation, and the IPv4 and IPv6
	// documentation and benchmarking ranges, are not public either.
	for _, cidr := range internalRanges {
		if cidr.Contains(addr) {
			return true
		}
	}

	return false
}

var internalRanges = func() []netip.Prefix {
	raw := []string{
		"100.64.0.0/10",   // carrier-grade translation
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"240.0.0.0/4",     // reserved
		"64:ff9b::/96",    // IPv4/IPv6 translation
		"100::/64",        // discard-only
		"2001:db8::/32",   // documentation
		"fc00::/7",        // unique local
	}

	out := make([]netip.Prefix, 0, len(raw))

	for _, s := range raw {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}

	return out
}()
