package main

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	probeBudget          = 1500 * time.Millisecond
	probeParallel        = 3
	hedgeDelay           = 250 * time.Millisecond
	maxProbes            = 9
	candidateCacheTTL    = 300 * time.Second
	failedSearchCacheTTL = 30 * time.Second
	rejectedHostCacheTTL = time.Hour
)

type addrIter func() (netip.Addr, bool)

// neighbourAddresses yields addresses of the same prefix, nearest first: the
// three closest (what xdp.es would pick), then alternating with other /24
// (or /112) blocks in case the whole block is cut. With sameBlock only the
// address's own /24 (/112) is used.
func neighbourAddresses(a netip.Addr, prefix netip.Prefix, sameBlock bool) addrIter {
	if sameBlock {
		if block := addressBlock(a); block.Bits() >= prefix.Bits() {
			prefix = block
		}
	}
	first, last := prefixRange(prefix)
	is4 := a.Is4()
	value := addrToU128(a)
	var near, far func() (u128, bool)
	if is4 {
		base := value.lo &^ 0xFF
		octet := int(value.lo & 0xFF)
		offset, negative := 1, false
		near = func() (u128, bool) {
			for offset < 255 {
				c := octet + offset
				if negative {
					c = octet - offset
					offset++
				}
				negative = !negative
				if c >= 1 && c <= 254 {
					return u128{0, base + uint64(c)}, true
				}
			}
			return u128{}, false
		}
		farOctet := uint64(octet)
		if octet < 1 || octet > 254 {
			farOctet = 1
		}
		step, below := uint64(1), false
		far = func() (u128, bool) {
			for step < 1024 {
				jump := step * 256
				if !below {
					below = true
					return u128{0, base + jump + farOctet}, true
				}
				below = false
				step++
				if base >= jump {
					return u128{0, base - jump + farOctet}, true
				}
			}
			return u128{}, false
		}
	} else {
		offset, negative := uint64(1), false
		near = func() (u128, bool) {
			for offset <= 1024 {
				if !negative {
					negative = true
					if v, ok := value.add(offset); ok {
						return v, true
					}
					continue
				}
				negative = false
				o := offset
				offset++
				if v, ok := value.sub(o); ok {
					return v, true
				}
			}
			return u128{}, false
		}
		step, below := uint64(1), false
		far = func() (u128, bool) {
			for step < 1024 {
				jump := step * 65536
				if !below {
					below = true
					if v, ok := value.add(jump); ok {
						return v, true
					}
					continue
				}
				below = false
				step++
				if v, ok := value.sub(jump); ok {
					return v, true
				}
			}
			return u128{}, false
		}
	}

	initial := 0
	nearDone, farDone := false, sameBlock
	takeFar := true
	raw := func() (u128, bool) {
		for {
			if sameBlock || initial < 3 {
				if !nearDone {
					if v, ok := near(); ok {
						initial++
						return v, true
					}
					nearDone = true
				}
				if sameBlock {
					return u128{}, false
				}
				initial = 3
			}
			if nearDone && farDone {
				return u128{}, false
			}
			useFar := takeFar
			takeFar = !takeFar
			if useFar && !farDone {
				if v, ok := far(); ok {
					return v, true
				}
				farDone = true
			} else if !useFar && !nearDone {
				if v, ok := near(); ok {
					return v, true
				}
				nearDone = true
			}
		}
	}
	return func() (netip.Addr, bool) {
		for {
			v, ok := raw()
			if !ok {
				return netip.Addr{}, false
			}
			if first.cmp(v) <= 0 && v.cmp(last) <= 0 {
				return u128ToAddr(v, is4), true
			}
		}
	}
}

type selectorKey struct {
	host      string
	addr      netip.Addr
	sameBlock bool
}

type cachedCandidate struct {
	expires   time.Time
	candidate netip.Addr // invalid (zero) when no candidate was found
}

type CandidateSelector struct {
	Probe     func(hostname string, a netip.Addr) ProbeResult
	Reach     *Reachability
	Budget    time.Duration
	Parallel  int
	MaxProbes int

	mu       sync.Mutex
	cache    *lru[selectorKey, cachedCandidate]
	lastGood *lru[netip.Addr, netip.Addr]
	rejected *lru[string, time.Time]
	inflight map[selectorKey]chan struct{}
}

func newCandidateSelector(probe func(string, netip.Addr) ProbeResult, reach *Reachability) *CandidateSelector {
	return &CandidateSelector{
		Probe:     probe,
		Reach:     reach,
		Budget:    probeBudget,
		Parallel:  probeParallel,
		MaxProbes: maxProbes,
		cache:     newLRU[selectorKey, cachedCandidate](maxCacheEntries),
		lastGood:  newLRU[netip.Addr, netip.Addr](maxCacheEntries),
		rejected:  newLRU[string, time.Time](maxCacheEntries),
		inflight:  map[selectorKey]chan struct{}{},
	}
}

func (s *CandidateSelector) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache.Len()
}

func sortAddrs(addrs []netip.Addr) {
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
}

// ChooseMany chooses replacements for several addresses at once, without
// repeating a candidate. Addresses in sameBlock only accept neighbours of
// their own /24 (/112).
func (s *CandidateSelector) ChooseMany(hostname string, addrs []netip.Addr, policy *Policy,
	exclude map[netip.Addr]bool, sameBlock map[netip.Addr]bool) map[netip.Addr]netip.Addr {
	ordered := append([]netip.Addr(nil), addrs...)
	sortAddrs(ordered)
	chosen := map[netip.Addr]netip.Addr{}
	if len(ordered) == 0 {
		return chosen
	}
	results := make([]netip.Addr, len(ordered))
	var wg sync.WaitGroup
	for i, a := range ordered {
		wg.Add(1)
		go func(i int, a netip.Addr) {
			defer wg.Done()
			results[i], _ = s.Choose(hostname, a, policy, exclude, sameBlock[a])
		}(i, a)
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(s.Budget + time.Second):
		return chosen // never block an answer beyond the budget
	}
	used := map[netip.Addr]bool{}
	for a := range exclude {
		used[a] = true
	}
	for i, a := range ordered {
		if candidate := results[i]; candidate.IsValid() && !used[candidate] {
			used[candidate] = true
			chosen[a] = candidate
		}
	}
	return chosen
}

func (s *CandidateSelector) Choose(hostname string, blocked netip.Addr, policy *Policy,
	exclude map[netip.Addr]bool, sameBlock bool) (netip.Addr, bool) {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	prefix, ok := policy.CloudflarePrefix(blocked)
	if !ok || hostname == "" {
		return netip.Addr{}, false
	}
	s.mu.Lock()
	rejectedUntil, rejected := s.rejected.Get(hostname)
	s.mu.Unlock()
	if rejected && time.Now().Before(rejectedUntil) {
		return netip.Addr{}, false
	}
	area := prefix
	if sameBlock {
		if block := addressBlock(blocked); block.Bits() >= prefix.Bits() {
			area = block
		}
	}
	key := selectorKey{hostname, blocked, sameBlock}

	if candidate, hit := s.cached(key); hit {
		if !candidate.IsValid() {
			return netip.Addr{}, false
		}
		if s.usable(candidate, blocked, area, policy, exclude) {
			return candidate, true
		}
	}

	s.mu.Lock()
	wait, busy := s.inflight[key]
	if !busy {
		wait = make(chan struct{})
		s.inflight[key] = wait
	}
	s.mu.Unlock()
	if busy {
		select {
		case <-wait:
		case <-time.After(s.Budget + 500*time.Millisecond):
		}
		if candidate, hit := s.cached(key); hit && candidate.IsValid() && s.usable(candidate, blocked, area, policy, exclude) {
			return candidate, true
		}
		return netip.Addr{}, false
	}
	defer func() {
		s.mu.Lock()
		delete(s.inflight, key)
		s.mu.Unlock()
		close(wait)
	}()

	candidate, lifetime, reached := s.search(hostname, blocked, area, policy, exclude, sameBlock)
	if sameBlock && !candidate.IsValid() && !reached && s.Reach != nil {
		// Nothing around it answers on 443: a non-web service, not an ISP block.
		s.Reach.MarkDark(blocked)
		lifetime = darkBlockLifetime
	}
	s.mu.Lock()
	if lifetime == rejectedHostCacheTTL {
		// Not a Cloudflare-proxied web name: skip all its addresses for a while.
		s.rejected.Set(hostname, time.Now().Add(lifetime))
	}
	s.cache.Set(key, cachedCandidate{time.Now().Add(lifetime), candidate})
	if candidate.IsValid() {
		s.lastGood.Set(blocked, candidate)
	}
	s.mu.Unlock()
	return candidate, candidate.IsValid()
}

func (s *CandidateSelector) cached(key selectorKey) (netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache.Get(key)
	if !ok {
		return netip.Addr{}, false
	}
	if !time.Now().Before(entry.expires) {
		s.cache.Delete(key)
		return netip.Addr{}, false
	}
	return entry.candidate, true
}

func (s *CandidateSelector) usable(candidate, original netip.Addr, area netip.Prefix, policy *Policy,
	exclude map[netip.Addr]bool) bool {
	if candidate == original || candidate.BitLen() != original.BitLen() || exclude[candidate] {
		return false
	}
	if !area.Contains(candidate) || candidate == area.Masked().Addr() || candidate == lastAddress(area) {
		return false
	}
	if !candidate.IsGlobalUnicast() || candidate.IsPrivate() {
		return false
	}
	if candidate.Is4() {
		if last := candidate.As4()[3]; last == 0 || last == 255 {
			return false
		}
	}
	if policy.IsListed(candidate) {
		return false
	}
	return s.Reach == nil || !s.Reach.IsDown(candidate)
}

func (s *CandidateSelector) candidates(original netip.Addr, area netip.Prefix, policy *Policy,
	exclude map[netip.Addr]bool, sameBlock bool) addrIter {
	var preferred []netip.Addr
	s.mu.Lock()
	if last, ok := s.lastGood.Get(original); ok {
		preferred = append(preferred, last)
	}
	s.mu.Unlock()
	var knownUp []netip.Addr
	if s.Reach != nil {
		knownUp = s.Reach.RecentlyUp(area, 3)
	}
	neighbours := neighbourAddresses(original, area, sameBlock)
	seen := map[netip.Addr]bool{}
	stage, initial, knownIndex, takeKnown := 0, 0, 0, true
	neighboursDone := false
	nextNeighbour := func() (netip.Addr, bool) {
		if neighboursDone {
			return netip.Addr{}, false
		}
		a, ok := neighbours()
		if !ok {
			neighboursDone = true
		}
		return a, ok
	}
	raw := func() (netip.Addr, bool) {
		for {
			switch {
			case stage == 0 && len(preferred) > 0:
				a := preferred[0]
				preferred = preferred[1:]
				return a, true
			case stage == 0:
				stage = 1
			case stage == 1 && initial < 3:
				initial++
				if a, ok := nextNeighbour(); ok {
					return a, true
				}
				stage = 2
			case stage == 1:
				stage = 2
			default:
				if knownIndex >= len(knownUp) && neighboursDone {
					return netip.Addr{}, false
				}
				useKnown := takeKnown
				takeKnown = !takeKnown
				if useKnown && knownIndex < len(knownUp) {
					knownIndex++
					return knownUp[knownIndex-1], true
				}
				if !useKnown {
					if a, ok := nextNeighbour(); ok {
						return a, true
					}
				}
			}
		}
	}
	return func() (netip.Addr, bool) {
		for {
			a, ok := raw()
			if !ok {
				return netip.Addr{}, false
			}
			if seen[a] {
				continue
			}
			seen[a] = true
			if s.usable(a, original, area, policy, exclude) {
				return a, true
			}
		}
	}
}

type probeOutcome struct {
	order     int
	candidate netip.Addr
	result    ProbeResult
}

// search returns the candidate (invalid if none), how long to cache the
// outcome and whether any candidate accepted a TCP connection.
func (s *CandidateSelector) search(hostname string, original netip.Addr, area netip.Prefix, policy *Policy,
	exclude map[netip.Addr]bool, sameBlock bool) (netip.Addr, time.Duration, bool) {
	started := time.Now()
	deadline := started.Add(s.Budget)
	next := s.candidates(original, area, policy, exclude, sameBlock)
	outcomes := make(chan probeOutcome, s.MaxProbes)
	pending, launched := 0, 0
	exhausted, reached := false, false
	// The nearest candidate alone first; others join if it is slow or fails.
	width := 1
	for {
		for !exhausted && pending < width && launched < s.MaxProbes {
			candidate, ok := next()
			if !ok {
				exhausted = true
				break
			}
			go func(order int, candidate netip.Addr) {
				outcomes <- probeOutcome{order, candidate, s.probe(hostname, candidate)}
			}(launched, candidate)
			pending++
			launched++
		}
		now := time.Now()
		remaining := deadline.Sub(now)
		if pending == 0 || remaining <= 0 {
			break
		}
		wait := remaining
		if width < s.Parallel {
			wait = min(remaining, max(0, started.Add(hedgeDelay).Sub(now)))
		}
		timer := time.NewTimer(wait)
		var batch []probeOutcome
		select {
		case outcome := <-outcomes:
			batch = append(batch, outcome)
		case <-timer.C:
		}
		timer.Stop()
		if len(batch) == 0 {
			if width < s.Parallel {
				width = s.Parallel
				continue
			}
			break
		}
	drain:
		for {
			select {
			case outcome := <-outcomes:
				batch = append(batch, outcome)
			default:
				break drain
			}
		}
		pending -= len(batch)
		width = s.Parallel
		sort.Slice(batch, func(i, j int) bool { return batch[i].order < batch[j].order })
		rejected := false
		for _, outcome := range batch {
			if outcome.result != probeUnreachable {
				reached = true
			}
			if outcome.result == probeRejected {
				rejected = true
			}
		}
		for _, outcome := range batch {
			if outcome.result == probeOK {
				infof("Candidata TLS válida para %s: %s (sustituye a %s)", hostname, outcome.candidate, original)
				return outcome.candidate, candidateCacheTTL, true
			}
		}
		if rejected {
			// Every Cloudflare edge presents the same certificate for a
			// name, so a rejection here will repeat on any neighbour.
			infof("Cloudflare no presenta un certificado válido para %s cerca de %s; se deja la respuesta original",
				hostname, original)
			return netip.Addr{}, rejectedHostCacheTTL, true
		}
	}
	if sameBlock {
		infof("No se encontró candidata TLS para %s (origen bloqueado: %s)", hostname, original)
	} else {
		warnf("No se encontró candidata TLS para %s (origen bloqueado: %s)", hostname, original)
	}
	return netip.Addr{}, failedSearchCacheTTL, reached
}

func (s *CandidateSelector) probe(hostname string, candidate netip.Addr) ProbeResult {
	result := s.Probe(hostname, candidate)
	if s.Reach != nil {
		s.Reach.Record(candidate, result != probeUnreachable)
	}
	return result
}
