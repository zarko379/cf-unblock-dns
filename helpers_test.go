package main

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	cfV4      = netip.MustParsePrefix("104.16.0.0/13")
	cfV6      = netip.MustParsePrefix("2606:4700::/32")
	blockedV4 = netip.MustParseAddr("104.21.1.10")
	blockedV6 = netip.MustParseAddr("2606:4700:3030::6815:10a")
)

func ip(value string) netip.Addr { return netip.MustParseAddr(value) }

func testPolicy(blocked ...string) *Policy {
	if blocked == nil {
		blocked = []string{blockedV4.String(), blockedV6.String()}
	}
	var networks []netip.Prefix
	for _, value := range blocked {
		p, err := parseNetwork(value)
		if err != nil {
			panic(err)
		}
		networks = append(networks, p)
	}
	return newPolicy(networks, []netip.Prefix{cfV4, cfV6})
}

func always(result ProbeResult) func(string, netip.Addr) ProbeResult {
	return func(string, netip.Addr) ProbeResult { return result }
}

func testSelector(probe func(string, netip.Addr) ProbeResult, reach *Reachability) *CandidateSelector {
	if probe == nil {
		probe = always(probeOK)
	}
	s := newCandidateSelector(probe, reach)
	s.Budget = time.Second
	return s
}

func testReach(check func(netip.Addr, uint16, time.Duration) bool) *Reachability {
	r := newReachability(nil)
	r.Check = check
	return r
}

type testRR struct {
	owner string
	rtype uint16
	ttl   uint32
	rdata []byte
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func aRR(owner, value string) testRR {
	b := ip(value).As4()
	return testRR{owner, typeA, 300, b[:]}
}

func aaaaRR(owner, value string) testRR {
	b := ip(value).As16()
	return testRR{owner, typeAAAA, 300, b[:]}
}

func cnameRR(owner, target string) testRR {
	return testRR{owner, 5, 300, encodeName(target)}
}

func httpsRR(owner string, v4, v6 []string) testRR {
	rdata := []byte{0, 1, 0}                       // priority 1, target "."
	rdata = append(rdata, 0, 1, 0, 3, 2, 'h', '2') // alpn=h2
	if len(v4) > 0 {
		rdata = binary.BigEndian.AppendUint16(rdata, svcParamIPv4Hint)
		rdata = binary.BigEndian.AppendUint16(rdata, uint16(4*len(v4)))
		for _, value := range v4 {
			b := ip(value).As4()
			rdata = append(rdata, b[:]...)
		}
	}
	if len(v6) > 0 {
		rdata = binary.BigEndian.AppendUint16(rdata, svcParamIPv6Hint)
		rdata = binary.BigEndian.AppendUint16(rdata, uint16(16*len(v6)))
		for _, value := range v6 {
			b := ip(value).As16()
			rdata = append(rdata, b[:]...)
		}
	}
	return testRR{owner, typeHTTPS, 300, rdata}
}

func rrsigRR(owner string, covered uint16) testRR {
	rdata := binary.BigEndian.AppendUint16(nil, covered)
	rdata = append(rdata, 13, 2, 0, 0, 1, 44, 0, 0, 0, 1, 0, 0, 0, 1, 0x30, 0x39)
	rdata = append(rdata, encodeName(owner)...)
	rdata = append(rdata, make([]byte, 64)...)
	return testRR{owner, typeRRSIG, 300, rdata}
}

func buildMessage(qname string, qtype uint16, flags uint16, do bool, records []testRR, ttl uint32) []byte {
	wire := make([]byte, 12)
	binary.BigEndian.PutUint16(wire[0:], 0xBEEF)
	binary.BigEndian.PutUint16(wire[2:], flags)
	binary.BigEndian.PutUint16(wire[4:], 1)
	binary.BigEndian.PutUint16(wire[6:], uint16(len(records)))
	if do {
		binary.BigEndian.PutUint16(wire[10:], 1)
	}
	wire = append(wire, encodeName(qname)...)
	wire = binary.BigEndian.AppendUint16(wire, qtype)
	wire = binary.BigEndian.AppendUint16(wire, 1)
	for _, r := range records {
		if strings.TrimSuffix(r.owner, ".") == strings.TrimSuffix(qname, ".") {
			wire = append(wire, 0xC0, 0x0C) // compression pointer to the question
		} else {
			wire = append(wire, encodeName(r.owner)...)
		}
		wire = binary.BigEndian.AppendUint16(wire, r.rtype)
		wire = binary.BigEndian.AppendUint16(wire, 1)
		recordTTL := r.ttl
		if ttl != 0 {
			recordTTL = ttl
		}
		wire = binary.BigEndian.AppendUint32(wire, recordTTL)
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(r.rdata)))
		wire = append(wire, r.rdata...)
	}
	if do {
		wire = append(wire, 0, 0, typeOPT, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0)
	}
	return wire
}

func query(qname string, qtype uint16, do bool) []byte {
	return buildMessage(qname, qtype, flagRD, do, nil, 0)
}

func response(qname string, qtype uint16, ad, do bool, ttl uint32, records ...testRR) []byte {
	flags := uint16(flagQR | flagRD | flagRA)
	if ad {
		flags |= flagAD
	}
	return buildMessage(qname, qtype, flags, do, records, ttl)
}

func mustQuery(t *testing.T, wire []byte) QueryInfo {
	t.Helper()
	info, ok := parseQuery(wire)
	if !ok {
		t.Fatal("consulta no válida")
	}
	return info
}

func answerAddrs(t *testing.T, wire []byte, rtype uint16) []string {
	t.Helper()
	msg, err := parseMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range msg.Records {
		if r.Section == 1 && r.Type == rtype {
			out = append(out, slotAddr(wire, addrSlot{r.RDataOffset, r.RDLength, r.Type}).String())
		}
	}
	sort.Strings(out)
	return out
}

func answerTTLs(t *testing.T, wire []byte) []uint32 {
	t.Helper()
	msg, err := parseMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	var out []uint32
	for _, r := range msg.Records {
		if r.Section == 1 {
			out = append(out, be32(wire, r.TTLOffset))
		}
	}
	return out
}

func hints(t *testing.T, wire []byte) []string {
	t.Helper()
	msg, err := parseMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range msg.Records {
		if r.Type == typeHTTPS {
			for _, slot := range svcbHintSlots(wire, r) {
				out = append(out, slotAddr(wire, slot).String())
			}
		}
	}
	return out
}

func hasAD(wire []byte) bool { return be16(wire, 2)&flagAD != 0 }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
