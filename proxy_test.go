package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() { currentLevel = levelError }

// --- wire format -------------------------------------------------------------

func TestParseQueryReadsNameTypeAndDO(t *testing.T) {
	info := mustQuery(t, query("Site.Example.", typeAAAA, true))
	if info != (QueryInfo{"site.example", typeAAAA, true}) {
		t.Fatalf("%+v", info)
	}
	if mustQuery(t, query("site.example.", typeA, false)).DNSSECOK {
		t.Fatal("DO inesperado")
	}
}

func TestMalformedMessages(t *testing.T) {
	if _, ok := parseQuery([]byte{0, 1}); ok {
		t.Fatal("cabecera truncada aceptada")
	}
	wire := query("site.example.", typeA, false)
	if _, ok := parseQuery(wire[:len(wire)-3]); ok {
		t.Fatal("pregunta truncada aceptada")
	}
	loop := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1}
	if _, ok := parseQuery(loop); ok {
		t.Fatal("bucle de compresión aceptado")
	}
	huge := []byte{0, 1, 0x80, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0}
	if _, err := parseMessage(huge); err == nil {
		t.Fatal("contadores imposibles aceptados")
	}
}

func TestResponsesAreNotQueries(t *testing.T) {
	if _, ok := parseQuery(response("site.example.", typeA, false, false, 0, aRR("site.example.", "192.0.2.1"))); ok {
		t.Fatal("respuesta tratada como consulta")
	}
}

func TestServfailKeepsIDAndQuestion(t *testing.T) {
	wire := query("site.example.", typeA, false)
	fail := servfailFor(wire)
	msg, err := parseMessage(fail)
	if err != nil || fail[0] != wire[0] || fail[1] != wire[1] || msg.Flags&rcodeMask != rcodeFail ||
		msg.Questions[0].Name != "site.example" {
		t.Fatalf("SERVFAIL incorrecto: %v %+v", err, msg)
	}
}

func TestSNIHostname(t *testing.T) {
	if sniHostname("WWW.Example.com.") != "www.example.com" {
		t.Fatal("nombre válido rechazado")
	}
	for _, name := range []string{"localhost", "_dmarc.example.com", "1.2.3.4", "bad_name.example.com", "-x.example.com"} {
		if sniHostname(name) != "" {
			t.Fatalf("%s aceptado", name)
		}
	}
}

func TestMalformedSVCBHintsAreIgnored(t *testing.T) {
	wire := []byte{0, 1, 0, 0, 4, 0, 3, 1, 2}
	if slots := svcbHintSlots(wire, Record{1, 0, typeHTTPS, 0, 0, 9}); slots != nil {
		t.Fatalf("%v", slots)
	}
}

// --- neighbours ----------------------------------------------------------------

func collect(next addrIter, limit int) []netip.Addr {
	var out []netip.Addr
	for len(out) < limit {
		a, ok := next()
		if !ok {
			break
		}
		out = append(out, a)
	}
	return out
}

func TestNearestNeighboursFirstAndInsidePrefix(t *testing.T) {
	candidates := collect(neighbourAddresses(blockedV4, cfV4, false), 100000)
	first := []string{candidates[0].String(), candidates[1].String(), candidates[2].String()}
	if !equalStrings(first, []string{"104.21.1.11", "104.21.1.9", "104.21.1.12"}) {
		t.Fatalf("orden: %v", first)
	}
	otherBlock := false
	for i, a := range candidates {
		if !cfV4.Contains(a) || a.As4()[3] == 0 || a.As4()[3] == 255 {
			t.Fatalf("candidata no válida %s", a)
		}
		if i < 10 && addressBlock(a) != addressBlock(blockedV4) {
			otherBlock = true
		}
	}
	if !otherBlock {
		t.Fatal("no se mezclan otros bloques")
	}
}

func TestNeighboursRespectSmallPrefixEdges(t *testing.T) {
	prefix := netip.MustParsePrefix("188.114.96.0/24")
	candidates := collect(neighbourAddresses(ip("188.114.96.1"), prefix, false), 1000)
	if len(candidates) != 253 {
		t.Fatalf("%d candidatas", len(candidates))
	}
	for _, a := range candidates {
		if !prefix.Contains(a) || a.String() == "188.114.96.0" || a.String() == "188.114.96.255" {
			t.Fatalf("candidata no válida %s", a)
		}
	}
}

func TestIPv6Neighbours(t *testing.T) {
	candidates := collect(neighbourAddresses(blockedV6, cfV6, false), 5000)
	if candidates[0] != blockedV6.Next() {
		t.Fatalf("primera candidata %s", candidates[0])
	}
	for _, a := range candidates {
		if !a.Is6() || !cfV6.Contains(a) {
			t.Fatalf("candidata no válida %s", a)
		}
	}
}

func TestSameBlockNeighbours(t *testing.T) {
	block := addressBlock(blockedV4)
	for _, a := range collect(neighbourAddresses(blockedV4, cfV4, true), 1000) {
		if !block.Contains(a) {
			t.Fatalf("%s fuera de %s", a, block)
		}
	}
}

// --- candidate selection --------------------------------------------------------

func TestSelectsUnblockedCandidateInSamePrefix(t *testing.T) {
	candidate, ok := testSelector(nil, nil).Choose("site.example.", blockedV4, testPolicy("104.21.1.10", "104.21.1.11"), nil, false)
	if !ok || candidate.String() != "104.21.1.9" {
		t.Fatalf("%s %v", candidate, ok)
	}
}

func TestProbeReceivesHostnameAndResultIsCached(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	selector := testSelector(func(host string, _ netip.Addr) ProbeResult {
		mu.Lock()
		calls = append(calls, host)
		mu.Unlock()
		return probeOK
	}, nil)
	first, _ := selector.Choose("Site.Example.", blockedV4, testPolicy(), nil, false)
	second, _ := selector.Choose("site.example", blockedV4, testPolicy(), nil, false)
	if first != second || len(calls) != 1 || calls[0] != "site.example" {
		t.Fatalf("%s %s %v", first, second, calls)
	}
}

func TestNoCandidateWhenProbesFail(t *testing.T) {
	if _, ok := testSelector(always(probeUnreachable), nil).Choose("site.example", blockedV4, testPolicy(), nil, false); ok {
		t.Fatal("candidata sin sonda válida")
	}
}

func TestCertificateRejectionStopsSearch(t *testing.T) {
	var calls atomic.Int32
	selector := testSelector(func(string, netip.Addr) ProbeResult { calls.Add(1); return probeRejected }, nil)
	if _, ok := selector.Choose("site.example", blockedV4, testPolicy(), nil, false); ok {
		t.Fatal("candidata pese al rechazo")
	}
	if calls.Load() > probeParallel {
		t.Fatalf("%d sondas", calls.Load())
	}
}

func TestRejectedHostnameIsRememberedForAllAddresses(t *testing.T) {
	var calls atomic.Int32
	selector := testSelector(func(string, netip.Addr) ProbeResult { calls.Add(1); return probeRejected }, nil)
	selector.Choose("ntp.example", blockedV4, testPolicy(), nil, false)
	before := calls.Load()
	other := ip("104.21.9.9")
	selector.Choose("ntp.example", other, testPolicy("104.21.1.10", "104.21.9.9"), nil, false)
	if calls.Load() != before {
		t.Fatal("se volvió a sondear un nombre rechazado")
	}
}

func TestSkipsAddressesKnownToBeDown(t *testing.T) {
	reach := testReach(func(netip.Addr, uint16, time.Duration) bool { return true })
	reach.Record(ip("104.21.1.11"), false)
	candidate, _ := testSelector(nil, reach).Choose("site.example", blockedV4, testPolicy(), nil, false)
	if candidate.String() != "104.21.1.9" {
		t.Fatalf("%s", candidate)
	}
}

func TestUnreachableProbeMarksAddressDown(t *testing.T) {
	reach := testReach(func(netip.Addr, uint16, time.Duration) bool { return true })
	selector := testSelector(func(_ string, a netip.Addr) ProbeResult {
		if a.String() == "104.21.1.11" {
			return probeUnreachable
		}
		return probeOK
	}, reach)
	selector.Parallel = 1
	candidate, _ := selector.Choose("site.example", blockedV4, testPolicy(), nil, false)
	if candidate.String() != "104.21.1.9" || !reach.IsDown(ip("104.21.1.11")) {
		t.Fatalf("%s", candidate)
	}
}

func TestChooseManySearchesInParallelWithoutDuplicates(t *testing.T) {
	selector := testSelector(func(string, netip.Addr) ProbeResult { time.Sleep(300 * time.Millisecond); return probeOK }, nil)
	var blocked []netip.Addr
	var values []string
	for n := 1; n <= 4; n++ {
		a := ip("104.21." + strconv.Itoa(n) + ".10")
		blocked = append(blocked, a)
		values = append(values, a.String())
	}
	exclude := map[netip.Addr]bool{}
	for _, a := range blocked {
		exclude[a] = true
	}
	started := time.Now()
	chosen := selector.ChooseMany("site.example", blocked, testPolicy(values...), exclude, nil)
	if time.Since(started) > 900*time.Millisecond {
		t.Fatalf("búsqueda secuencial: %s", time.Since(started))
	}
	unique := map[netip.Addr]bool{}
	for _, c := range chosen {
		unique[c] = true
	}
	if len(chosen) != 4 || len(unique) != 4 {
		t.Fatalf("%v", chosen)
	}
}

func TestOutsideCloudflareIsNeverReplaced(t *testing.T) {
	if _, ok := testSelector(nil, nil).Choose("site.example", ip("192.124.249.25"), testPolicy("192.124.249.25"), nil, false); ok {
		t.Fatal("sustitución fuera de Cloudflare")
	}
}

// --- rewriting -------------------------------------------------------------------

func rewrite(qname string, qtype uint16, do bool, wire []byte, policy *Policy, selector *CandidateSelector,
	reach *Reachability, online func(int) bool) RewriteResult {
	if policy == nil {
		policy = testPolicy()
	}
	if selector == nil {
		selector = testSelector(nil, reach)
	}
	if online == nil {
		online = func(int) bool { return true }
	}
	info, _ := parseQuery(query(qname, qtype, do))
	return rewriteResponse(info, wire, policy, selector, RewriteOptions{30, 30}, reach, online)
}

func TestRewritesListedCloudflareAInPlace(t *testing.T) {
	wire := response("site.example.", typeA, true, false, 0, aRR("site.example.", blockedV4.String()), aRR("site.example.", "172.67.1.1"))
	result := rewrite("site.example.", typeA, false, wire, nil, nil, nil, nil)
	if len(result.Wire) != len(wire) || hasAD(result.Wire) {
		t.Fatal("tamaño o AD incorrectos")
	}
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{"104.21.1.11", "172.67.1.1"}) {
		t.Fatalf("%v", got)
	}
	if ttls := answerTTLs(t, result.Wire); ttls[0] != 30 || ttls[1] != 30 {
		t.Fatalf("%v", ttls)
	}
	if bytes.Equal(wire, result.Wire) || result.Substitutions[blockedV4] != ip("104.21.1.11") {
		t.Fatal("sin sustitución")
	}
}

func TestNonCloudflareAnswerIsByteIdentical(t *testing.T) {
	wire := response("site.example.", typeA, true, false, 0, aRR("site.example.", "192.0.2.10"))
	if result := rewrite("site.example.", typeA, false, wire, testPolicy("192.0.2.10"), nil, nil, nil); !bytes.Equal(result.Wire, wire) {
		t.Fatal("respuesta modificada")
	}
}

func TestUnblockedCloudflareOnlyCapsTTL(t *testing.T) {
	wire := response("site.example.", typeA, true, false, 0, aRR("site.example.", "104.21.5.5"))
	result := rewrite("site.example.", typeA, false, wire, nil, nil, nil, nil)
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{"104.21.5.5"}) || !hasAD(result.Wire) ||
		answerTTLs(t, result.Wire)[0] != 30 || len(result.Substitutions) != 0 {
		t.Fatal("resultado incorrecto")
	}
}

func TestTTLCapNeverRaisesAndCanBeDisabled(t *testing.T) {
	wire := response("site.example.", typeA, false, false, 12, aRR("site.example.", "104.21.5.5"))
	if ttl := answerTTLs(t, rewrite("site.example.", typeA, false, wire, nil, nil, nil, nil).Wire)[0]; ttl != 12 {
		t.Fatalf("TTL %d", ttl)
	}
	wire = response("site.example.", typeA, false, false, 0, aRR("site.example.", "104.21.5.5"))
	info, _ := parseQuery(query("site.example.", typeA, false))
	disabled := rewriteResponse(info, wire, testPolicy(), testSelector(nil, nil), RewriteOptions{0, 30}, nil,
		func(int) bool { return true })
	if !bytes.Equal(disabled.Wire, wire) {
		t.Fatal("TTL limitado con el límite desactivado")
	}
}

func TestDNSSECOKQueriesAreUntouched(t *testing.T) {
	wire := response("site.example.", typeA, true, true, 0, aRR("site.example.", blockedV4.String()))
	if result := rewrite("site.example.", typeA, true, wire, nil, nil, nil, nil); !bytes.Equal(result.Wire, wire) {
		t.Fatal("consulta DO modificada")
	}
}

func TestKeepsOriginalWhenNoCandidateVerifies(t *testing.T) {
	wire := response("site.example.", typeA, true, false, 0, aRR("site.example.", blockedV4.String()))
	result := rewrite("site.example.", typeA, false, wire, nil, testSelector(always(probeUnreachable), nil), nil, nil)
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{blockedV4.String()}) || !hasAD(result.Wire) ||
		answerTTLs(t, result.Wire)[0] != 30 {
		t.Fatal("resultado incorrecto")
	}
}

func TestRewritesAAAA(t *testing.T) {
	wire := response("site.example.", typeAAAA, false, false, 0, aaaaRR("site.example.", blockedV6.String()))
	result := rewrite("site.example.", typeAAAA, false, wire, nil, nil, nil, nil)
	if got := answerAddrs(t, result.Wire, typeAAAA); !equalStrings(got, []string{blockedV6.Next().String()}) {
		t.Fatalf("%v", got)
	}
}

func TestCNAMEChainUsesQueryNameForTLS(t *testing.T) {
	var hosts sync.Map
	selector := testSelector(func(host string, _ netip.Addr) ProbeResult { hosts.Store(host, true); return probeOK }, nil)
	wire := response("www.site.example.", typeA, false, false, 0,
		cnameRR("www.site.example.", "site.example.cdn.cloudflare.net."),
		aRR("site.example.cdn.cloudflare.net.", blockedV4.String()))
	result := rewrite("www.site.example.", typeA, false, wire, nil, selector, nil, nil)
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{"104.21.1.11"}) {
		t.Fatalf("%v", got)
	}
	count := 0
	hosts.Range(func(key, _ any) bool {
		count++
		if key != "www.site.example" {
			t.Fatalf("SNI %v", key)
		}
		return true
	})
	if ttls := answerTTLs(t, result.Wire); count != 1 || ttls[0] != 30 || ttls[1] != 30 {
		t.Fatalf("%d %v", count, ttls)
	}
}

func TestRewritesHTTPSHints(t *testing.T) {
	wire := response("site.example.", typeHTTPS, false, false, 0,
		httpsRR("site.example.", []string{blockedV4.String(), "104.21.5.5"}, []string{blockedV6.String()}))
	result := rewrite("site.example.", typeHTTPS, false, wire, nil, nil, nil, nil)
	got := hints(t, result.Wire)
	want := []string{"104.21.1.11", "104.21.5.5", blockedV6.Next().String()}
	if !equalStrings(got, want) || len(result.Wire) != len(wire) {
		t.Fatalf("%v", got)
	}
}

func TestSignedAnswerIsNotRewritten(t *testing.T) {
	wire := response("site.example.", typeA, false, false, 0, aRR("site.example.", blockedV4.String()), rrsigRR("site.example.", typeA))
	result := rewrite("site.example.", typeA, false, wire, nil, nil, nil, nil)
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{blockedV4.String()}) || len(result.Substitutions) != 0 {
		t.Fatal("respuesta firmada reescrita")
	}
}

func TestTruncatedAndErrorResponsesPassThrough(t *testing.T) {
	wire := response("site.example.", typeA, false, false, 0, aRR("site.example.", blockedV4.String()))
	truncated := append([]byte(nil), wire...)
	truncated[2] |= 0x02
	if result := rewrite("site.example.", typeA, false, truncated, nil, nil, nil, nil); !bytes.Equal(result.Wire, truncated) {
		t.Fatal("respuesta truncada modificada")
	}
	failed := append([]byte(nil), wire...)
	failed[3] = failed[3]&0xF0 | 2
	if result := rewrite("site.example.", typeA, false, failed, nil, nil, nil, nil); !bytes.Equal(result.Wire, failed) {
		t.Fatal("SERVFAIL modificado")
	}
}

func TestLocalDetectionRewritesUnlistedUnreachableAddress(t *testing.T) {
	down := ip("104.21.9.9")
	reach := testReach(func(a netip.Addr, _ uint16, _ time.Duration) bool { return a != down })
	wire := response("site.example.", typeA, false, false, 0, aRR("site.example.", down.String()), aRR("site.example.", "104.21.5.5"))
	result := rewrite("site.example.", typeA, false, wire, nil, testSelector(nil, reach), reach, nil)
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{"104.21.5.5", "104.21.9.10"}) || !result.Detected[down] {
		t.Fatalf("%v", got)
	}
}

func TestNonWebBlockIsNotTreatedAsBlocked(t *testing.T) {
	reach := testReach(func(netip.Addr, uint16, time.Duration) bool { return false })
	var probes atomic.Int32
	selector := testSelector(func(string, netip.Addr) ProbeResult { probes.Add(1); return probeOK }, reach)
	ntp := []string{"104.21.200.1", "104.21.200.123", "104.21.200.5"}
	var records []testRR
	for _, value := range ntp {
		records = append(records, aRR("time.example.", value))
	}
	result := rewrite("time.example.", typeA, false, response("time.example.", typeA, false, false, 0, records...), nil, selector, reach, nil)
	if len(result.Substitutions) != 0 || probes.Load() != 0 {
		t.Fatal("servicio no web reescrito")
	}
	var checked atomic.Int32
	reach.Check = func(netip.Addr, uint16, time.Duration) bool { checked.Add(1); return false }
	rewrite("time.example.", typeA, false, response("time.example.", typeA, false, false, 0, aRR("time.example.", "104.21.200.77")),
		nil, selector, reach, nil)
	if checked.Load() != 0 {
		t.Fatal("se comprobó una dirección de un bloque ya marcado")
	}
}

func TestLocalDetectionOnlyUsesSameBlockAndMarksDarkBlocks(t *testing.T) {
	down := ip("104.21.9.9")
	block := netip.MustParsePrefix("104.21.9.0/24")
	reach := testReach(func(a netip.Addr, _ uint16, _ time.Duration) bool { return a != down })
	selector := testSelector(func(_ string, a netip.Addr) ProbeResult {
		if block.Contains(a) {
			return probeUnreachable
		}
		return probeOK
	}, reach)
	wire := response("site.example.", typeA, false, false, 0, aRR("site.example.", down.String()))
	result := rewrite("site.example.", typeA, false, wire, nil, selector, reach, nil)
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{down.String()}) || !reach.InDarkBlock(down) {
		t.Fatalf("%v", got)
	}
}

func TestListedAddressMayMoveToAnotherBlock(t *testing.T) {
	block := netip.MustParsePrefix("104.21.1.0/24")
	selector := testSelector(func(_ string, a netip.Addr) ProbeResult {
		if block.Contains(a) {
			return probeUnreachable
		}
		return probeOK
	}, nil)
	wire := response("site.example.", typeA, false, false, 0, aRR("site.example.", blockedV4.String()))
	replaced := ip(answerAddrs(t, rewrite("site.example.", typeA, false, wire, nil, selector, nil, nil).Wire, typeA)[0])
	if block.Contains(replaced) || !cfV4.Contains(replaced) {
		t.Fatalf("%s", replaced)
	}
}

func TestOfflineFamilyIsNeitherCheckedNorRewritten(t *testing.T) {
	var checked atomic.Int32
	reach := testReach(func(netip.Addr, uint16, time.Duration) bool { checked.Add(1); return false })
	wire := response("site.example.", typeAAAA, false, false, 0, aaaaRR("site.example.", blockedV6.String()), aaaaRR("site.example.", "2606:4700::5"))
	result := rewrite("site.example.", typeAAAA, false, wire, nil, nil, reach, func(v int) bool { return v == 4 })
	if len(result.Substitutions) != 0 || checked.Load() != 0 {
		t.Fatal("familia sin conectividad procesada")
	}
}

func TestInvalidSNINameOnlyCapsTTL(t *testing.T) {
	wire := response("_svc.site.example.", typeA, false, false, 0, aRR("_svc.site.example.", blockedV4.String()))
	result := rewrite("_svc.site.example.", typeA, false, wire, nil, nil, nil, nil)
	if got := answerAddrs(t, result.Wire, typeA); !equalStrings(got, []string{blockedV4.String()}) || answerTTLs(t, result.Wire)[0] != 30 {
		t.Fatal("resultado incorrecto")
	}
}

// --- reachability ---------------------------------------------------------------

func TestUnknownAddressesAreCheckedOnceAndCached(t *testing.T) {
	var calls atomic.Int32
	reach := testReach(func(netip.Addr, uint16, time.Duration) bool { calls.Add(1); return false })
	a := ip("104.21.9.9")
	if !reach.Unreachable([]netip.Addr{a})[a] || !reach.Unreachable([]netip.Addr{a})[a] || calls.Load() != 1 {
		t.Fatalf("%d comprobaciones", calls.Load())
	}
}

func TestSlowChecksDoNotCountAsBlocked(t *testing.T) {
	reach := testReach(func(netip.Addr, uint16, time.Duration) bool { time.Sleep(500 * time.Millisecond); return false })
	reach.Timeout = 50 * time.Millisecond
	if len(reach.Unreachable([]netip.Addr{ip("104.21.9.9")})) != 0 {
		t.Fatal("comprobación lenta tratada como bloqueo")
	}
}

// --- policy data -----------------------------------------------------------------

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Duration(len(content)) * time.Millisecond)
	_ = os.Chtimes(path, later, later)
}

const testData = `{"blocked":["104.21.1.10/32","104.22.0.0/24"],"cloudflare_v4":["104.16.0.0/13"],"cloudflare_v6":["2606:4700::/32"]}`

func TestPolicyReloadAndKeepPreviousOnCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	writeFile(t, path, testData)
	data := newPolicyData(path, "")
	data.CheckInterval = 0
	loaded := data.Get()
	if !loaded.IsListed(blockedV4) || !loaded.IsListed(ip("104.22.0.7")) {
		t.Fatal("datos no cargados")
	}
	if prefix, _ := loaded.CloudflarePrefix(blockedV4); prefix != cfV4 {
		t.Fatal("prefijo incorrecto")
	}
	writeFile(t, path, "{corrupt")
	if !data.Get().IsListed(blockedV4) {
		t.Fatal("datos perdidos con un fichero corrupto")
	}
	os.Remove(path)
	if !data.Get().IsListed(blockedV4) {
		t.Fatal("datos perdidos sin fichero")
	}
}

func TestManualExtraListIsMergedAndReloaded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	extra := filepath.Join(dir, "extra-blocked.txt")
	writeFile(t, path, testData)
	data := newPolicyData(path, extra)
	data.CheckInterval = 0
	if data.Get().IsListed(ip("104.16.123.96")) {
		t.Fatal("entrada manual inesperada")
	}
	writeFile(t, extra, "# prueba\n104.16.123.96\nbasura\n2606:4700::/48  # rango\n")
	current := data.Get()
	if !current.IsListed(ip("104.16.123.96")) || !current.IsListed(ip("2606:4700::1")) || !current.IsListed(blockedV4) {
		t.Fatal("lista manual no aplicada")
	}
	os.Remove(extra)
	if data.Get().IsListed(ip("104.16.123.96")) || !data.Get().IsListed(blockedV4) {
		t.Fatal("lista manual no retirada")
	}
}

// --- proxy ----------------------------------------------------------------------

type fakeUnbound struct {
	udp  *net.UDPConn
	tcp  net.Listener
	addr string
}

func startFakeUnbound(t *testing.T, answers ...string) *fakeUnbound {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUnbound{udp, tcp, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	answer := func(wire []byte) []byte {
		info, _ := parseQuery(wire)
		var records []testRR
		for _, value := range answers {
			records = append(records, aRR(info.QName, value))
		}
		out := response(info.QName, info.QType, false, false, 0, records...)
		copy(out[:2], wire[:2])
		return out
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, client, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(answer(buf[:n]), client)
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			var header [2]byte
			if _, err := io.ReadFull(conn, header[:]); err == nil {
				wire := make([]byte, binary.BigEndian.Uint16(header[:]))
				if _, err := io.ReadFull(conn, wire); err == nil {
					out := answer(wire)
					_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
				}
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() { udp.Close(); tcp.Close() })
	return f
}

func testProxy(t *testing.T, upstream string) *DNSProxy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.json")
	writeFile(t, path, `{"blocked":["`+blockedV4.String()+`/32"],"cloudflare_v4":["104.16.0.0/13"],"cloudflare_v6":["2606:4700::/32"]}`)
	return newDNSProxy(&Upstream{upstream, time.Second}, newPolicyData(path, ""), testSelector(nil, nil), nil, nil,
		RewriteOptions{30, 30})
}

func TestEndToEndUDPAndTCP(t *testing.T) {
	proxy := testProxy(t, startFakeUnbound(t, blockedV4.String()).addr)
	wire := query("site.example.", typeA, false)
	for _, tcp := range []bool{false, true} {
		answer := proxy.Handle(wire, tcp)
		if got := answerAddrs(t, answer, typeA); !equalStrings(got, []string{"104.21.1.11"}) || answer[0] != wire[0] {
			t.Fatalf("tcp=%v: %v", tcp, got)
		}
	}
}

func TestOtherQueryTypesPassThrough(t *testing.T) {
	proxy := testProxy(t, startFakeUnbound(t, blockedV4.String()).addr)
	if got := answerAddrs(t, proxy.Handle(query("site.example.", 16, false), false), typeA); !equalStrings(got, []string{blockedV4.String()}) {
		t.Fatalf("%v", got)
	}
}

func TestSlowUpstreamGetsNoAnswerSoTheClientRetries(t *testing.T) {
	silent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	proxy := testProxy(t, silent.LocalAddr().String())
	proxy.Upstream.Timeout = 200 * time.Millisecond
	if answer := proxy.Handle(query("slow.example.", typeA, false), false); answer != nil {
		t.Fatal("respuesta pese al tiempo agotado")
	}
	if proxy.Stats.Snapshot()["upstream_timeouts"] != 1 {
		t.Fatal("contador no incrementado")
	}
}

func TestUpstreamFailureReturnsServfail(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	address := listener.Addr().String()
	listener.Close()
	proxy := testProxy(t, address)
	answer := proxy.Handle(query("site.example.", typeA, false), true)
	if answer == nil || be16(answer, 2)&rcodeMask != rcodeFail {
		t.Fatal("se esperaba SERVFAIL")
	}
	if proxy.Handle([]byte{0}, true) != nil {
		t.Fatal("respuesta a una consulta ilegible")
	}
}

func TestRewriteLogIsRateLimited(t *testing.T) {
	proxy := testProxy(t, "127.0.0.1:1")
	if !proxy.shouldLog("site.example A x") || proxy.shouldLog("site.example A x") || !proxy.shouldLog("other A x") {
		t.Fatal("límite de registro incorrecto")
	}
}

func TestTCPUpstreamRetriesOnceWhenUnboundClosesTheConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		first, err := listener.Accept()
		if err != nil {
			return
		}
		first.Close() // no slot: closed without an answer
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		wire := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(conn, wire); err != nil {
			return
		}
		info, _ := parseQuery(wire)
		out := response(info.QName, info.QType, false, false, 0, aRR(info.QName, "192.0.2.7"))
		copy(out[:2], wire[:2])
		_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
	}()
	proxy := testProxy(t, listener.Addr().String())
	if got := answerAddrs(t, proxy.Handle(query("site.example.", typeA, false), true), typeA); !equalStrings(got, []string{"192.0.2.7"}) {
		t.Fatalf("%v", got)
	}
	if proxy.Stats.Snapshot()["upstream_failures"] != 0 {
		t.Fatal("se contó como fallo pese al reintento")
	}
}
