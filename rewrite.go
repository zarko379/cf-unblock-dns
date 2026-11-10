package main

import (
	"encoding/binary"
	"net/netip"
)

const (
	defaultCloudflareMaxTTL = 30 // same as xdp.es: a new block reaches clients within half a minute
	defaultRewrittenTTL     = 30
)

type RewriteOptions struct {
	CloudflareMaxTTL uint32
	RewrittenTTL     uint32
}

type RewriteResult struct {
	Wire          []byte
	Substitutions map[netip.Addr]netip.Addr
	Detected      map[netip.Addr]bool
	Listed        map[netip.Addr]bool
	Cloudflare    bool
	TTLCapped     bool
}

func slotAddr(wire []byte, slot addrSlot) netip.Addr {
	if slot.Size == 4 {
		return netip.AddrFrom4([4]byte(wire[slot.Offset : slot.Offset+4]))
	}
	return netip.AddrFrom16([16]byte(wire[slot.Offset : slot.Offset+16]))
}

// rewriteResponse replaces blocked Cloudflare addresses in place. Answers
// without Cloudflare addresses and DNSSEC (DO) queries are returned as is.
func rewriteResponse(query QueryInfo, wire []byte, policy *Policy, selector *CandidateSelector, opts RewriteOptions,
	reach *Reachability, online func(int) bool) RewriteResult {
	unchanged := RewriteResult{Wire: wire}
	// A changed address could never match its signature.
	if query.DNSSECOK {
		return unchanged
	}
	msg, err := parseMessage(wire)
	if err != nil || msg.Flags&flagQR == 0 || msg.Flags&flagTC != 0 || msg.Flags&rcodeMask != 0 {
		return unchanged
	}

	var slots []addrSlot
	for _, r := range msg.Records {
		switch {
		case r.Type == typeA && r.RDLength == 4:
			slots = append(slots, addrSlot{r.RDataOffset, 4, typeA})
		case r.Type == typeAAAA && r.RDLength == 16:
			slots = append(slots, addrSlot{r.RDataOffset, 16, typeAAAA})
		case r.Type == typeSVCB || r.Type == typeHTTPS:
			slots = append(slots, svcbHintSlots(wire, r)...)
		}
	}
	if len(slots) == 0 {
		return unchanged
	}

	addresses := make([]netip.Addr, len(slots))
	inUse := map[netip.Addr]bool{}
	var cloudflare []netip.Addr
	seenCF := map[netip.Addr]bool{}
	for i, slot := range slots {
		a := slotAddr(wire, slot)
		addresses[i] = a
		inUse[a] = true
		if _, ok := policy.CloudflarePrefix(a); ok && !seenCF[a] {
			seenCF[a] = true
			cloudflare = append(cloudflare, a)
		}
	}
	if len(cloudflare) == 0 {
		return unchanged
	}

	listed := map[netip.Addr]bool{}
	blocked := map[netip.Addr]bool{}
	for _, a := range cloudflare {
		if policy.IsListed(a) {
			listed[a] = true
			blocked[a] = true
		}
	}
	detected := map[netip.Addr]bool{}
	hostname := sniHostname(query.QName)
	if hostname != "" && reach != nil {
		var unknown []netip.Addr
		for _, a := range cloudflare {
			if !blocked[a] && online(familyOf(a)) && !reach.DarkMarked(a) {
				unknown = append(unknown, a)
			}
		}
		if len(unknown) > 0 {
			// Addresses whose whole /24 refuses 443 are non-web services
			// (NTP, WARP...), not ISP blocks.
			for a := range reach.Unreachable(unknown) {
				if !reach.InDarkBlock(a) {
					detected[a] = true
					blocked[a] = true
				}
			}
		}
	}

	substitutions := map[netip.Addr]netip.Addr{}
	if hostname != "" && len(blocked) > 0 {
		var eligible []netip.Addr
		for a := range blocked {
			if online(familyOf(a)) {
				eligible = append(eligible, a)
			}
		}
		// Locally detected addresses only move within their own /24: an ISP
		// cuts individual addresses, so a neighbour must answer.
		substitutions = selector.ChooseMany(hostname, eligible, policy, inUse, detected)
	}

	if len(substitutions) > 0 {
		changedTypes := map[uint16]bool{}
		for i, slot := range slots {
			if _, ok := substitutions[addresses[i]]; ok {
				changedTypes[slot.Type] = true
			}
		}
		for _, r := range msg.Records {
			if r.Type == typeRRSIG && r.RDLength >= 2 && changedTypes[be16(wire, r.RDataOffset)] {
				infof("Respuesta firmada para %s: no se reescribe", query.QName)
				substitutions = map[netip.Addr]netip.Addr{}
				break
			}
		}
	}

	limit := opts.CloudflareMaxTTL
	if len(substitutions) > 0 {
		limit = opts.RewrittenTTL
	}
	out := wire
	copied := false
	ensureCopy := func() {
		if !copied {
			out = append([]byte(nil), wire...)
			copied = true
		}
	}
	for i, slot := range slots {
		if replacement, ok := substitutions[addresses[i]]; ok {
			ensureCopy()
			if slot.Size == 4 {
				b := replacement.As4()
				copy(out[slot.Offset:], b[:])
			} else {
				b := replacement.As16()
				copy(out[slot.Offset:], b[:])
			}
		}
	}
	capped := false
	if limit > 0 {
		// Cap the whole response so CNAMEs and addresses expire together; a
		// lower TTL never invalidates a DNSSEC signature.
		for _, r := range msg.Records {
			if isTTLExempt(r.Type) {
				continue
			}
			if be32(out, r.TTLOffset) > limit {
				ensureCopy()
				binary.BigEndian.PutUint32(out[r.TTLOffset:], limit)
				capped = true
			}
		}
	}
	if len(substitutions) > 0 {
		ensureCopy()
		binary.BigEndian.PutUint16(out[2:], msg.Flags&^flagAD)
	}
	return RewriteResult{out, substitutions, detected, listed, true, capped}
}
