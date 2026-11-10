package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

const (
	typeA     = 1
	typeAAAA  = 28
	typeOPT   = 41
	typeRRSIG = 46
	typeSVCB  = 64
	typeHTTPS = 65
	typeTKEY  = 249
	typeTSIG  = 250
	typeANY   = 255

	flagQR     = 0x8000
	flagTC     = 0x0200
	flagRD     = 0x0100
	flagRA     = 0x0080
	flagAD     = 0x0020
	opcodeMask = 0x7800
	rcodeMask  = 0x000F
	rcodeFail  = 2
	ednsFlagDO = 0x8000

	svcParamIPv4Hint = 4
	svcParamIPv6Hint = 6
)

var errMalformed = errors.New("mensaje DNS malformado")

func isProcessedQType(qtype uint16) bool {
	switch qtype {
	case typeA, typeAAAA, typeSVCB, typeHTTPS, typeANY:
		return true
	}
	return false
}

func isTTLExempt(rtype uint16) bool {
	return rtype == typeOPT || rtype == typeTKEY || rtype == typeTSIG
}

func typeName(qtype uint16) string {
	switch qtype {
	case typeA:
		return "A"
	case typeAAAA:
		return "AAAA"
	case typeSVCB:
		return "SVCB"
	case typeHTTPS:
		return "HTTPS"
	case typeANY:
		return "ANY"
	}
	return strconv.Itoa(int(qtype))
}

type Record struct {
	Section     int // 1 answer, 2 authority, 3 additional
	NameOffset  int
	Type        uint16
	TTLOffset   int
	RDataOffset int
	RDLength    int
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type Message struct {
	Flags       uint16
	Questions   []Question
	QuestionEnd int
	Records     []Record
}

type QueryInfo struct {
	QName    string
	QType    uint16
	DNSSECOK bool
}

// readName decodes a possibly compressed name, lower-cased, and returns the
// offset right after it in the original position.
func readName(wire []byte, pos int) (string, int, error) {
	var b strings.Builder
	end := -1
	jumps := 0
	total := 0
	for {
		if pos >= len(wire) {
			return "", 0, errMalformed
		}
		length := int(wire[pos])
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(wire) {
				return "", 0, errMalformed
			}
			if end < 0 {
				end = pos + 2
			}
			jumps++
			if jumps > 64 {
				return "", 0, errMalformed
			}
			pos = (length&0x3F)<<8 | int(wire[pos+1])
			continue
		}
		if length&0xC0 != 0 {
			return "", 0, errMalformed
		}
		pos++
		if length == 0 {
			break
		}
		if pos+length > len(wire) {
			return "", 0, errMalformed
		}
		total += length + 1
		if total > 255 {
			return "", 0, errMalformed
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		for _, c := range wire[pos : pos+length] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b.WriteByte(c)
		}
		pos += length
	}
	if end < 0 {
		end = pos
	}
	return b.String(), end, nil
}

func skipName(wire []byte, pos int) (int, error) {
	for {
		if pos >= len(wire) {
			return 0, errMalformed
		}
		length := int(wire[pos])
		if length&0xC0 == 0xC0 {
			if pos+2 > len(wire) {
				return 0, errMalformed
			}
			return pos + 2, nil
		}
		if length&0xC0 != 0 {
			return 0, errMalformed
		}
		pos += 1 + length
		if length == 0 {
			return pos, nil
		}
	}
}

func be16(wire []byte, pos int) uint16 { return binary.BigEndian.Uint16(wire[pos:]) }
func be32(wire []byte, pos int) uint32 { return binary.BigEndian.Uint32(wire[pos:]) }

func parseMessage(wire []byte) (*Message, error) {
	if len(wire) < 12 {
		return nil, errMalformed
	}
	msg := &Message{Flags: be16(wire, 2)}
	qdcount, ancount := int(be16(wire, 4)), int(be16(wire, 6))
	nscount, arcount := int(be16(wire, 8)), int(be16(wire, 10))
	pos := 12
	for i := 0; i < qdcount; i++ {
		name, next, err := readName(wire, pos)
		if err != nil {
			return nil, err
		}
		if next+4 > len(wire) {
			return nil, errMalformed
		}
		msg.Questions = append(msg.Questions, Question{name, be16(wire, next), be16(wire, next+2)})
		pos = next + 4
	}
	msg.QuestionEnd = pos
	total := ancount + nscount + arcount
	if total > len(wire)/11 {
		// Every record needs at least 11 bytes: the counts cannot be real.
		return nil, errMalformed
	}
	msg.Records = make([]Record, 0, total)
	for i := 0; i < total; i++ {
		section := 3
		if i < ancount {
			section = 1
		} else if i < ancount+nscount {
			section = 2
		}
		nameOffset := pos
		next, err := skipName(wire, pos)
		if err != nil {
			return nil, err
		}
		if next+10 > len(wire) {
			return nil, errMalformed
		}
		rdlength := int(be16(wire, next+8))
		rdata := next + 10
		if rdata+rdlength > len(wire) {
			return nil, errMalformed
		}
		msg.Records = append(msg.Records, Record{section, nameOffset, be16(wire, next), next + 4, rdata, rdlength})
		pos = rdata + rdlength
	}
	return msg, nil
}

func parseQuery(wire []byte) (QueryInfo, bool) {
	msg, err := parseMessage(wire)
	if err != nil || msg.Flags&flagQR != 0 || len(msg.Questions) != 1 {
		return QueryInfo{}, false
	}
	do := false
	for _, r := range msg.Records {
		if r.Type == typeOPT && be32(wire, r.TTLOffset)&ednsFlagDO != 0 {
			do = true
		}
	}
	q := msg.Questions[0]
	return QueryInfo{QName: q.Name, QType: q.Type, DNSSECOK: do}, true
}

func buildQuery(qname string, qtype uint16) []byte {
	var id [2]byte
	_, _ = rand.Read(id[:])
	wire := make([]byte, 12, 12+len(qname)+6)
	copy(wire, id[:])
	binary.BigEndian.PutUint16(wire[2:], flagRD)
	binary.BigEndian.PutUint16(wire[4:], 1)
	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		if label == "" {
			continue
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return wire
}

func servfailFor(query []byte) []byte {
	msg, err := parseMessage(query)
	if err != nil || len(msg.Questions) != 1 {
		return nil
	}
	out := make([]byte, 12, msg.QuestionEnd)
	copy(out, query[:2])
	flags := uint16(flagQR|flagRA|rcodeFail) | msg.Flags&(opcodeMask|flagRD)
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], 1)
	return append(out, query[12:msg.QuestionEnd]...)
}

// sniHostname returns qname when a TLS client could send it as SNI.
func sniHostname(qname string) string {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	labels := strings.Split(name, ".")
	if len(labels) < 2 || len(name) > 253 || isDigits(labels[len(labels)-1]) {
		return ""
	}
	for _, label := range labels {
		if !validLabel(label) {
			return ""
		}
	}
	return name
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

type addrSlot struct {
	Offset int
	Size   int
	Type   uint16
}

// svcbHintSlots finds each address inside ipv4hint/ipv6hint of an SVCB/HTTPS record.
func svcbHintSlots(wire []byte, r Record) []addrSlot {
	end := r.RDataOffset + r.RDLength
	if r.RDLength < 3 {
		return nil
	}
	priority := be16(wire, r.RDataOffset)
	pos := r.RDataOffset + 2
	// TargetName is never compressed (RFC 9460); bail out on anything odd.
	for {
		if pos >= end {
			return nil
		}
		length := int(wire[pos])
		if length&0xC0 != 0 {
			return nil
		}
		pos += 1 + length
		if length == 0 {
			break
		}
	}
	if priority == 0 {
		return nil
	}
	var slots []addrSlot
	for pos+4 <= end {
		key, length := be16(wire, pos), int(be16(wire, pos+2))
		pos += 4
		valueEnd := pos + length
		if valueEnd > end {
			return nil
		}
		switch key {
		case svcParamIPv4Hint:
			if length%4 != 0 {
				return nil
			}
			for off := pos; off < valueEnd; off += 4 {
				slots = append(slots, addrSlot{off, 4, r.Type})
			}
		case svcParamIPv6Hint:
			if length%16 != 0 {
				return nil
			}
			for off := pos; off < valueEnd; off += 16 {
				slots = append(slots, addrSlot{off, 16, r.Type})
			}
		}
		pos = valueEnd
	}
	return slots
}
