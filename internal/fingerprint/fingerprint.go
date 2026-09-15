// Package fingerprint captures TLS ClientHello data and derives JA3
// fingerprints. The ClientHello is parsed from the raw bytes read off the
// connection *before* the TLS handshake, so the fingerprint is available to
// the HTTP handler (which the standard crypto/tls API does not expose).
package fingerprint

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"
)

// Hello is the ClientHello subset we care about, in wire order.
type Hello struct {
	Version      uint16
	Ciphers      []uint16
	Curves       []uint16 // from supported_groups (ext 0x000A)
	PointFormats []uint8  // from ec_point_formats (ext 0x000B)
	Extensions   []uint16 // all extension types, wire order
	Compression  []uint8
	SNI          string
	ALPN         []string
}

// JA3 returns the standard JA3 hash: SHA1 over
// "tls_version,ciphers,curves,point_formats,extensions" (list items
// comma-joined, groups dash-joined).
func (h *Hello) JA3() string {
	if h == nil {
		return ""
	}
	parts := []string{
		strconv.Itoa(int(h.Version)),
		joinU16(h.Ciphers),
		joinU16(h.Curves),
		joinU8(h.PointFormats),
		joinU16(h.Extensions),
	}
	sum := sha1.Sum([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])
}

func joinU16(v []uint16) string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.Itoa(int(x))
	}
	return strings.Join(out, "-")
}

func joinU8(v []uint8) string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.Itoa(int(x))
	}
	return strings.Join(out, "-")
}

func u16(b []byte, i int) uint16 { return uint16(b[i])<<8 | uint16(b[i+1]) }

// ParseClientHello extracts Hello fields from raw connection bytes
// (one or more TLS records carrying a ClientHello handshake message).
// It returns nil when the data is not a ClientHello or is truncated.
// Best-effort by design: a honeypot never fails a handshake over a
// fingerprint it could not parse.
func ParseClientHello(data []byte) *Hello {
	h := &Hello{}

	// Walk TLS records, accumulating the ClientHello handshake message.
	var hs []byte
	var hsLen int
	off := 0
	for off+5 <= len(data) {
		if data[off] != 0x16 { // 0x16 = handshake record
			return nil
		}
		recLen := int(data[off+3])<<8 | int(data[off+4]) // header: type(1) version(2) len(2)
		if recLen < 1 || off+5+recLen > len(data) {
			return nil // truncated record
		}
		rec := data[off+5 : off+5+recLen]
		if hs == nil {
			if len(rec) < 4 || rec[0] != 0x01 { // 0x01 = ClientHello
				return nil
			}
			hsLen = int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
			hs = make([]byte, 0, hsLen)
			hs = append(hs, rec[4:]...)
		} else {
			hs = append(hs, rec...)
		}
		off += 5 + recLen
		if len(hs) >= hsLen {
			break
		}
	}
	if hs == nil || len(hs) < hsLen {
		return nil
	}

	body := hs[:hsLen]
	pos, end := 0, len(body)
	get := func(n int) []byte {
		if pos+n > end {
			return nil
		}
		b := body[pos : pos+n]
		pos += n
		return b
	}
	if get(2+32) == nil {
		return nil
	}
	h.Version = u16(body, 0)
	pos = 34 // skip version + random
	sid := get(1)
	if sid == nil {
		return nil
	}
	pos += int(sid[0])
	csLen := get(2)
	if csLen == nil {
		return nil
	}
	cs := int(csLen[0])<<8 | int(csLen[1])
	ciphers := get(cs)
	if ciphers == nil {
		return nil
	}
	for i := 0; i+1 < len(ciphers); i += 2 {
		h.Ciphers = append(h.Ciphers, u16(ciphers, i))
	}
	compLen := get(1)
	if compLen == nil {
		return nil
	}
	comp := get(int(compLen[0]))
	if comp == nil {
		return nil
	}
	h.Compression = append(h.Compression, comp...)
	extLen := get(2)
	if extLen == nil {
		return nil
	}
	extEnd := pos + (int(extLen[0])<<8 | int(extLen[1]))
	if extEnd > end {
		extEnd = end
	}
	for pos+4 <= extEnd {
		et := u16(body, pos)
		el := int(u16(body, pos+2))
		pos += 4
		if pos+el > extEnd {
			break
		}
		ed := body[pos : pos+el]
		pos += el
		h.Extensions = append(h.Extensions, et)
		switch et {
		case 0x0000: // server_name
			if len(ed) >= 5 {
				nameLen := int(u16(ed, 3))
				if 5+nameLen <= len(ed) {
					h.SNI = string(ed[5 : 5+nameLen])
				}
			}
		case 0x000A: // supported_groups
			if len(ed) >= 2 {
				n := int(u16(ed, 0))
				for i := 2; i+2 <= 2+n && i+2 <= len(ed); i += 2 {
					h.Curves = append(h.Curves, u16(ed, i))
				}
			}
		case 0x000B: // ec_point_formats
			if len(ed) >= 1 {
				n := int(ed[0])
				for i := 1; i < 1+n && i < len(ed); i++ {
					h.PointFormats = append(h.PointFormats, ed[i])
				}
			}
		case 0x0010: // application_layer_protocol_negotiation
			if len(ed) >= 2 {
				n := int(u16(ed, 0))
				p := 2
				for p < 2+n && p < len(ed) {
					l := int(ed[p])
					p++
					if p+l > len(ed) {
						break
					}
					h.ALPN = append(h.ALPN, string(ed[p:p+l]))
					p += l
				}
			}
		}
	}
	return h
}
