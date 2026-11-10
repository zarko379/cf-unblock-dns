package main

import (
	"container/list"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	reachabilityTimeout    = 350 * time.Millisecond
	probeTimeout           = 800 * time.Millisecond
	reachableFresh         = 120 * time.Second
	unreachableFresh       = 30 * time.Second
	reachabilityStale      = 900 * time.Second
	darkBlockLifetime      = time.Hour
	familySuccessWindow    = 600 * time.Second
	maxReachabilityEntries = 8192
	maxCacheEntries        = 4096
	maxConcurrentProbes    = 32
	familyCheckDialTimeout = 2 * time.Second
)

type ProbeResult int

const (
	probeOK ProbeResult = iota
	probeUnreachable
	probeRejected
)

// Root servers answer TCP/53 from any network and are what Unbound talks to
// anyway; they tell whether an address family works at all from this host.
var rootServers = map[int][]string{
	4: {"198.41.0.4", "199.9.14.201", "193.0.14.129"},
	6: {"2001:503:ba3e::2:30", "2001:500:200::b", "2001:7fe::53"},
}

// probeSlots bounds how many probes run at once, like a worker pool.
var probeSlots = make(chan struct{}, maxConcurrentProbes)

func tcpConnect(a netip.Addr, port uint16, timeout time.Duration) bool {
	probeSlots <- struct{}{}
	defer func() { <-probeSlots }()
	conn, err := net.DialTimeout("tcp", netip.AddrPortFrom(a, port).String(), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func familyOf(a netip.Addr) int {
	if a.Is4() {
		return 4
	}
	return 6
}

// TLSProber completes a TLS handshake with SNI and full certificate validation.
type TLSProber struct {
	Timeout time.Duration
}

func (p TLSProber) Probe(hostname string, a netip.Addr) ProbeResult {
	probeSlots <- struct{}{}
	defer func() { <-probeSlots }()
	conn, err := net.DialTimeout("tcp", netip.AddrPortFrom(a, 443).String(), p.Timeout)
	if err != nil {
		return probeUnreachable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.Timeout))
	client := tls.Client(conn, &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12})
	err = client.Handshake()
	if err == nil {
		return probeOK
	}
	// A certificate problem or a TLS alert means the edge answered but will
	// not serve this name; resets, EOFs and timeouts mean the path is cut.
	var certErr *tls.CertificateVerificationError
	var alert tls.AlertError
	if errors.As(err, &certErr) || errors.As(err, &alert) {
		return probeRejected
	}
	return probeUnreachable
}

// FamilyMonitor tracks whether IPv4/IPv6 connectivity works from this host.
type FamilyMonitor struct {
	Connect func(netip.Addr, uint16, time.Duration) bool

	mu          sync.Mutex
	online      map[int]bool
	lastSuccess map[int]time.Time
}

func newFamilyMonitor() *FamilyMonitor {
	return &FamilyMonitor{
		Connect:     tcpConnect,
		online:      map[int]bool{4: true, 6: true},
		lastSuccess: map[int]time.Time{},
	}
}

func (f *FamilyMonitor) Online(version int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.online[version]
}

func (f *FamilyMonitor) Snapshot() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]bool{"ipv4": f.online[4], "ipv6": f.online[6]}
}

func (f *FamilyMonitor) Observe(version int, ok bool) {
	if !ok {
		return
	}
	f.mu.Lock()
	f.lastSuccess[version] = time.Now()
	f.mu.Unlock()
	f.set(version, true)
}

func (f *FamilyMonitor) Refresh(policy *Policy) {
	type target struct {
		addr netip.Addr
		port uint16
	}
	type family struct {
		version int
		answers chan bool
		count   int
	}
	var checks []family
	for _, version := range []int{4, 6} {
		f.mu.Lock()
		last, seen := f.lastSuccess[version]
		f.mu.Unlock()
		if seen && time.Since(last) < familySuccessWindow {
			f.set(version, true)
			continue
		}
		var targets []target
		for _, value := range rootServers[version] {
			targets = append(targets, target{netip.MustParseAddr(value), 53})
		}
		if policy != nil {
			added := 0
			// policy.cloudflare is most specific first: the largest prefixes are last.
			for i := len(policy.cloudflare) - 1; i >= 0 && added < 3; i-- {
				if prefix := policy.cloudflare[i]; familyOf(prefix.Addr()) == version {
					targets = append(targets, target{prefixMiddle(prefix), 443})
					added++
				}
			}
		}
		answers := make(chan bool, len(targets))
		for _, t := range targets {
			go func(t target) { answers <- f.Connect(t.addr, t.port, familyCheckDialTimeout) }(t)
		}
		checks = append(checks, family{version, answers, len(targets)})
	}
	for _, check := range checks {
		f.collect(check.version, check.answers, check.count)
	}
}

func (f *FamilyMonitor) collect(version int, ch chan bool, n int) {
	ok := false
	for i := 0; i < n; i++ {
		if <-ch {
			ok = true
			break
		}
	}
	if ok {
		f.Observe(version, true)
	} else {
		f.set(version, false)
	}
}

func (f *FamilyMonitor) set(version int, value bool) {
	f.mu.Lock()
	previous, known := f.online[version]
	f.online[version] = value
	f.mu.Unlock()
	if known && previous == value {
		return
	}
	if value {
		infof("Conectividad IPv%d disponible desde este equipo", version)
	} else {
		warnf("Sin conectividad IPv%d desde este equipo: no se comprueban ni sustituyen direcciones IPv%d", version, version)
	}
}

// lru is a small least-recently-used map. Not safe for concurrent use.
type lru[K comparable, V any] struct {
	max   int
	order *list.List
	items map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	key   K
	value V
}

func newLRU[K comparable, V any](max int) *lru[K, V] {
	return &lru[K, V]{max: max, order: list.New(), items: map[K]*list.Element{}}
}

func (c *lru[K, V]) Get(key K) (V, bool) {
	if element, ok := c.items[key]; ok {
		return element.Value.(*lruEntry[K, V]).value, true
	}
	var zero V
	return zero, false
}

func (c *lru[K, V]) Set(key K, value V) {
	if element, ok := c.items[key]; ok {
		element.Value.(*lruEntry[K, V]).value = value
		c.order.MoveToFront(element)
		return
	}
	c.items[key] = c.order.PushFront(&lruEntry[K, V]{key, value})
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*lruEntry[K, V]).key)
	}
}

func (c *lru[K, V]) Delete(key K) {
	if element, ok := c.items[key]; ok {
		c.order.Remove(element)
		delete(c.items, key)
	}
}

func (c *lru[K, V]) Len() int { return c.order.Len() }

// Each visits entries from newest to oldest until fn returns false.
func (c *lru[K, V]) Each(fn func(K, V) bool) {
	for element := c.order.Front(); element != nil; element = element.Next() {
		entry := element.Value.(*lruEntry[K, V])
		if !fn(entry.key, entry.value) {
			return
		}
	}
}

type reachEntry struct {
	ok      bool
	checked time.Time
}

type reachCheck struct {
	done chan struct{}
	ok   bool
}

// Reachability remembers whether Cloudflare addresses accept TCP/443 from this host.
type Reachability struct {
	Check    func(netip.Addr, uint16, time.Duration) bool
	Timeout  time.Duration
	Families *FamilyMonitor

	mu       sync.Mutex
	entries  *lru[netip.Addr, reachEntry]
	inflight map[netip.Addr]*reachCheck
	dark     *lru[netip.Prefix, time.Time]
}

func newReachability(families *FamilyMonitor) *Reachability {
	return &Reachability{
		Check:    tcpConnect,
		Timeout:  reachabilityTimeout,
		Families: families,
		entries:  newLRU[netip.Addr, reachEntry](maxReachabilityEntries),
		inflight: map[netip.Addr]*reachCheck{},
		dark:     newLRU[netip.Prefix, time.Time](maxCacheEntries),
	}
}

func (r *Reachability) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries.Len()
}

func (r *Reachability) Record(a netip.Addr, ok bool) {
	r.mu.Lock()
	previous, known := r.entries.Get(a)
	r.entries.Set(a, reachEntry{ok, time.Now()})
	r.mu.Unlock()
	if r.Families != nil {
		r.Families.Observe(familyOf(a), ok)
	}
	if !ok && (!known || previous.ok) {
		infof("Sin conexión TCP/443 desde este equipo a %s", a)
	} else if ok && known && !previous.ok {
		infof("%s vuelve a aceptar conexiones", a)
	}
}

func (r *Reachability) IsDown(a netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries.Get(a)
	return ok && !entry.ok && time.Since(entry.checked) < reachabilityStale
}

func (r *Reachability) MarkDark(a netip.Addr) {
	block := addressBlock(a)
	r.mu.Lock()
	r.dark.Set(block, time.Now().Add(darkBlockLifetime))
	r.mu.Unlock()
	infof("%s no sirve HTTPS desde ninguna dirección cercana: se trata como servicio no web", block)
}

// DarkMarked is the cheap hot-path check: block already known to be non-web.
func (r *Reachability) DarkMarked(a netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.dark.Get(addressBlock(a))
	return ok && time.Now().Before(until)
}

// InDarkBlock reports that nothing near the address serves TCP/443: a
// non-web endpoint (NTP, WARP...), not an ISP block.
func (r *Reachability) InDarkBlock(a netip.Addr) bool {
	if r.DarkMarked(a) {
		return true
	}
	block := addressBlock(a)
	up, down := 0, 0
	r.mu.Lock()
	r.entries.Each(func(other netip.Addr, entry reachEntry) bool {
		if time.Since(entry.checked) < reachabilityStale && block.Contains(other) {
			if entry.ok {
				up++
			} else {
				down++
			}
		}
		return true
	})
	r.mu.Unlock()
	if up == 0 && down >= 2 {
		r.MarkDark(a)
		return true
	}
	return false
}

func (r *Reachability) RecentlyUp(area netip.Prefix, limit int) []netip.Addr {
	var found []netip.Addr
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries.Each(func(a netip.Addr, entry reachEntry) bool {
		if entry.ok && time.Since(entry.checked) < reachableFresh && area.Contains(a) {
			found = append(found, a)
		}
		return len(found) < limit
	})
	return found
}

// Unreachable returns the addresses that do not answer, checking unknown
// ones synchronously within the timeout.
func (r *Reachability) Unreachable(addresses []netip.Addr) map[netip.Addr]bool {
	down := map[netip.Addr]bool{}
	var pending []netip.Addr
	checks := map[netip.Addr]*reachCheck{}
	now := time.Now()
	for _, a := range addresses {
		r.mu.Lock()
		entry, known := r.entries.Get(a)
		r.mu.Unlock()
		if known {
			age := now.Sub(entry.checked)
			fresh := reachableFresh
			if !entry.ok {
				fresh = unreachableFresh
			}
			if age < fresh {
				if !entry.ok {
					down[a] = true
				}
				continue
			}
			if age < reachabilityStale {
				// Stale but usable: answer now, refresh in the background.
				if !entry.ok {
					down[a] = true
				}
				r.submit(a)
				continue
			}
		}
		pending = append(pending, a)
		checks[a] = r.submit(a)
	}
	if len(pending) == 0 {
		return down
	}
	deadline := time.NewTimer(r.Timeout + 50*time.Millisecond)
	defer deadline.Stop()
wait:
	for _, a := range pending {
		select {
		case <-checks[a].done:
		case <-deadline.C:
			break wait
		}
	}
	for _, a := range pending {
		// Checks still running count as reachable: never delay or rewrite
		// an answer on a guess.
		select {
		case <-checks[a].done:
			if !checks[a].ok {
				down[a] = true
			}
		default:
		}
	}
	return down
}

func (r *Reachability) submit(a netip.Addr) *reachCheck {
	r.mu.Lock()
	defer r.mu.Unlock()
	if check, ok := r.inflight[a]; ok {
		return check
	}
	check := &reachCheck{done: make(chan struct{})}
	r.inflight[a] = check
	go func() {
		ok := r.Check(a, 443, r.Timeout)
		r.Record(a, ok)
		r.mu.Lock()
		delete(r.inflight, a)
		r.mu.Unlock()
		check.ok = ok
		close(check.done)
	}()
	return check
}
