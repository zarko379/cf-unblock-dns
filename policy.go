package main

import (
	"encoding/json"
	"errors"
	"math/bits"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// u128 holds an IPv4 (low 32 bits) or IPv6 address as a number.
type u128 struct{ hi, lo uint64 }

func addrToU128(a netip.Addr) u128 {
	if a.Is4() {
		b := a.As4()
		return u128{0, uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])}
	}
	b := a.As16()
	var v u128
	for i := 0; i < 8; i++ {
		v.hi = v.hi<<8 | uint64(b[i])
		v.lo = v.lo<<8 | uint64(b[i+8])
	}
	return v
}

func u128ToAddr(v u128, is4 bool) netip.Addr {
	if is4 {
		return netip.AddrFrom4([4]byte{byte(v.lo >> 24), byte(v.lo >> 16), byte(v.lo >> 8), byte(v.lo)})
	}
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[7-i] = byte(v.hi >> (8 * i))
		b[15-i] = byte(v.lo >> (8 * i))
	}
	return netip.AddrFrom16(b)
}

func (v u128) add(n uint64) (u128, bool) {
	lo, carry := bits.Add64(v.lo, n, 0)
	hi, overflow := bits.Add64(v.hi, 0, carry)
	return u128{hi, lo}, overflow == 0
}

func (v u128) sub(n uint64) (u128, bool) {
	lo, borrow := bits.Sub64(v.lo, n, 0)
	hi, underflow := bits.Sub64(v.hi, 0, borrow)
	return u128{hi, lo}, underflow == 0
}

func (v u128) cmp(w u128) int {
	switch {
	case v.hi < w.hi || v.hi == w.hi && v.lo < w.lo:
		return -1
	case v == w:
		return 0
	}
	return 1
}

func lowMask(n int) u128 {
	switch {
	case n <= 0:
		return u128{}
	case n < 64:
		return u128{0, 1<<uint(n) - 1}
	case n == 64:
		return u128{0, ^uint64(0)}
	case n < 128:
		return u128{1<<uint(n-64) - 1, ^uint64(0)}
	}
	return u128{^uint64(0), ^uint64(0)}
}

func prefixRange(p netip.Prefix) (u128, u128) {
	first := addrToU128(p.Masked().Addr())
	mask := lowMask(p.Addr().BitLen() - p.Bits())
	return first, u128{first.hi | mask.hi, first.lo | mask.lo}
}

// prefixMiddle is an address in the middle of a prefix (used to test connectivity).
func prefixMiddle(p netip.Prefix) netip.Addr {
	first, _ := prefixRange(p)
	host := p.Addr().BitLen() - p.Bits()
	if host > 1 {
		half := lowMask(host - 1)
		mid, _ := u128{first.hi | half.hi, first.lo | half.lo}.add(2)
		return u128ToAddr(mid, p.Addr().Is4())
	}
	return p.Masked().Addr()
}

func addressBlock(a netip.Addr) netip.Prefix {
	bits := 112
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

func lastAddress(p netip.Prefix) netip.Addr {
	_, last := prefixRange(p)
	return u128ToAddr(last, p.Addr().Is4())
}

// parseNetwork accepts an address or a CIDR (host bits are cleared).
func parseNetwork(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if a.Zone() != "" {
		return netip.Prefix{}, errors.New("dirección con zona")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

type Policy struct {
	blockedHosts map[netip.Addr]struct{}
	blockedNets  []netip.Prefix
	cloudflare   []netip.Prefix // most specific first
}

func newPolicy(blocked, cloudflare []netip.Prefix) *Policy {
	p := &Policy{blockedHosts: make(map[netip.Addr]struct{}, len(blocked))}
	for _, network := range blocked {
		if network.IsSingleIP() {
			p.blockedHosts[network.Addr()] = struct{}{}
		} else {
			p.blockedNets = append(p.blockedNets, network)
		}
	}
	p.cloudflare = append([]netip.Prefix(nil), cloudflare...)
	sort.SliceStable(p.cloudflare, func(i, j int) bool { return p.cloudflare[i].Bits() > p.cloudflare[j].Bits() })
	return p
}

func (p *Policy) BlockedCount() int { return len(p.blockedHosts) + len(p.blockedNets) }

func (p *Policy) IsListed(a netip.Addr) bool {
	if _, ok := p.blockedHosts[a]; ok {
		return true
	}
	for _, network := range p.blockedNets {
		if network.Contains(a) {
			return true
		}
	}
	return false
}

func (p *Policy) CloudflarePrefix(a netip.Addr) (netip.Prefix, bool) {
	for _, prefix := range p.cloudflare {
		if prefix.Contains(a) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func (p *Policy) WithExtraBlocked(addresses []netip.Addr) *Policy {
	clone := &Policy{
		blockedHosts: make(map[netip.Addr]struct{}, len(p.blockedHosts)+len(addresses)),
		blockedNets:  p.blockedNets,
		cloudflare:   p.cloudflare,
	}
	for a := range p.blockedHosts {
		clone.blockedHosts[a] = struct{}{}
	}
	for _, a := range addresses {
		clone.blockedHosts[a] = struct{}{}
	}
	return clone
}

// PolicyData loads data.json written by the updater, keeping the last valid
// copy, plus an optional hand-maintained list of extra blocked addresses.
type PolicyData struct {
	Path          string
	ExtraPath     string
	CheckInterval time.Duration

	mu         sync.Mutex
	stamps     [2]int64
	nextCheck  time.Time
	blocked    []netip.Prefix
	cloudflare []netip.Prefix
	extra      []netip.Prefix
	policy     *Policy
	updatedAt  string
}

func newPolicyData(path, extraPath string) *PolicyData {
	return &PolicyData{
		Path:          path,
		ExtraPath:     extraPath,
		CheckInterval: time.Second,
		stamps:        [2]int64{-1, -1},
		policy:        newPolicy(nil, nil),
	}
}

func (d *PolicyData) UpdatedAt() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.updatedAt
}

func (d *PolicyData) Get() *Policy {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if now.Before(d.nextCheck) {
		return d.policy
	}
	d.nextCheck = now.Add(d.CheckInterval)
	dataStamp := fileStamp(d.Path, d.stamps[0])
	extraStamp := fileStamp(d.ExtraPath, d.stamps[1])
	if dataStamp == d.stamps[0] && extraStamp == d.stamps[1] {
		return d.policy
	}
	if dataStamp != d.stamps[0] && dataStamp != -1 {
		d.loadData()
	}
	if extraStamp != d.stamps[1] {
		d.loadExtra()
	}
	d.stamps = [2]int64{dataStamp, extraStamp}
	d.policy = newPolicy(append(append([]netip.Prefix(nil), d.blocked...), d.extra...), d.cloudflare)
	infof("Datos cargados: %d entradas bloqueadas (%d manuales), %d prefijos Cloudflare",
		d.policy.BlockedCount(), len(d.extra), len(d.policy.cloudflare))
	return d.policy
}

func fileStamp(path string, previous int64) int64 {
	if path == "" {
		return -1
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return -1
	}
	if err != nil {
		errorf("No se pudo consultar %s: %v", path, err)
		return previous
	}
	return info.ModTime().UnixNano() ^ info.Size()<<1
}

type dataFile struct {
	UpdatedAt    string    `json:"updated_at"`
	Blocked      *[]string `json:"blocked"`
	CloudflareV4 *[]string `json:"cloudflare_v4"`
	CloudflareV6 *[]string `json:"cloudflare_v6"`
}

// loadData keeps the previous data when data.json is missing or broken.
func (d *PolicyData) loadData() {
	raw, err := os.ReadFile(d.Path)
	if err != nil {
		errorf("Datos de políticas no válidos en %s (%v); se conservan los anteriores", d.Path, err)
		return
	}
	var data dataFile
	if err := json.Unmarshal(raw, &data); err != nil {
		errorf("Datos de políticas no válidos en %s (%v); se conservan los anteriores", d.Path, err)
		return
	}
	if data.Blocked == nil || data.CloudflareV4 == nil || data.CloudflareV6 == nil {
		errorf("Datos de políticas no válidos en %s (faltan claves); se conservan los anteriores", d.Path)
		return
	}
	blocked, err := parseNetworks(*data.Blocked, 0)
	if err != nil {
		errorf("Datos de políticas no válidos en %s (%v); se conservan los anteriores", d.Path, err)
		return
	}
	v4, err4 := parseNetworks(*data.CloudflareV4, 4)
	v6, err6 := parseNetworks(*data.CloudflareV6, 6)
	if err4 != nil || err6 != nil {
		errorf("Prefijos Cloudflare no válidos en %s; se conservan los anteriores", d.Path)
		return
	}
	d.blocked = blocked
	d.cloudflare = append(v4, v6...)
	d.updatedAt = data.UpdatedAt
}

func parseNetworks(values []string, version int) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		p, err := parseNetwork(value)
		if err != nil {
			return nil, err
		}
		if version == 4 && !p.Addr().Is4() || version == 6 && !p.Addr().Is6() {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (d *PolicyData) loadExtra() {
	raw, err := os.ReadFile(d.ExtraPath)
	if errors.Is(err, os.ErrNotExist) {
		d.extra = nil
		return
	}
	if err != nil {
		errorf("No se pudo leer %s (%v); se conserva la lista manual anterior", d.ExtraPath, err)
		return
	}
	var extra []netip.Prefix
	for _, line := range strings.Split(string(raw), "\n") {
		value := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if value == "" {
			continue
		}
		p, err := parseNetwork(value)
		if err != nil {
			if len(value) > 80 {
				value = value[:80]
			}
			warnf("Entrada ignorada en %s: %q", d.ExtraPath, value)
			continue
		}
		extra = append(extra, p)
	}
	d.extra = extra
}
