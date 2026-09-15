package fingerprint

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// buildClientHello assembles a minimal but valid ClientHello:
// version 0x0303, ciphers [0x1301, 0x1302, 0xC02B], curves [29, 23],
// point formats [0], extensions in wire order
// [sni(0), groups(10), point_formats(11), alpn(16), padding(21)],
// SNI "test.example", ALPN [h2, http/1.1].
func buildClientHello(t *testing.T) []byte {
	t.Helper()
	u16 := func(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

	buildExt := func(id uint16, body []byte) []byte {
		var e bytes.Buffer
		e.Write(u16(id))
		e.Write(u16(uint16(len(body))))
		e.Write(body)
		return e.Bytes()
	}

	// SNI extension body: list of one host_name "test.example".
	name := []byte("test.example")
	var sniList bytes.Buffer
	sniList.WriteByte(0x00)               // name_type: host_name
	sniList.Write(u16(uint16(len(name)))) // length
	sniList.Write(name)
	var sniBody bytes.Buffer
	sniBody.Write(u16(uint16(sniList.Len())))
	sniBody.Write(sniList.Bytes())

	// supported_groups body: [29, 23].
	var groupsBody bytes.Buffer
	groupsBody.Write(u16(4))
	groupsBody.Write(u16(29))
	groupsBody.Write(u16(23))

	// ec_point_formats body: [0].
	pointBody := []byte{0x01, 0x00}

	// ALPN body: ["h2", "http/1.1"].
	var alpnBody bytes.Buffer
	alpnBody.Write(u16(14))
	alpnBody.Write([]byte{0x02, 'h', '2'})
	alpnBody.Write([]byte{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})

	// padding: 32 zero bytes.
	padding := make([]byte, 32)

	var exts bytes.Buffer
	for _, e := range [][]byte{
		buildExt(0x0000, sniBody.Bytes()),
		buildExt(0x000A, groupsBody.Bytes()),
		buildExt(0x000B, pointBody),
		buildExt(0x0010, alpnBody.Bytes()),
		buildExt(0x0015, padding),
	} {
		exts.Write(e)
	}

	// ClientHello body.
	var ch bytes.Buffer
	ch.Write(u16(0x0303))      // legacy version TLS 1.2
	ch.Write(make([]byte, 32)) // random
	ch.Write([]byte{0x00})     // legacy session id: empty
	ch.Write(u16(6))           // cipher suites length
	for _, c := range []uint16{0x1301, 0x1302, 0xC02B} {
		ch.Write(u16(c))
	}
	ch.Write([]byte{0x01, 0x00}) // compression methods: null
	ch.Write(u16(uint16(exts.Len())))
	ch.Write(exts.Bytes())

	// Handshake message.
	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	hs.WriteByte(byte(len(ch.Bytes()) >> 16))
	hs.WriteByte(byte(len(ch.Bytes()) >> 8))
	hs.WriteByte(byte(len(ch.Bytes())))
	hs.Write(ch.Bytes())

	// TLS record.
	var rec bytes.Buffer
	rec.WriteByte(0x16)           // record type: handshake
	rec.Write([]byte{0x03, 0x01}) // record version: TLS 1.0 (always)
	rec.WriteByte(byte(len(hs.Bytes()) >> 8))
	rec.WriteByte(byte(len(hs.Bytes())))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func TestParseClientHello(t *testing.T) {
	h := ParseClientHello(buildClientHello(t))
	if h == nil {
		t.Fatal("parse returned nil")
	}
	if h.Version != 0x0303 {
		t.Errorf("version = %#x, want 0x0303", h.Version)
	}
	if got, want := len(h.Ciphers), 3; got != want {
		t.Fatalf("len(ciphers) = %d, want %d", got, want)
	}
	for i, want := range []uint16{0x1301, 0x1302, 0xC02B} {
		if h.Ciphers[i] != want {
			t.Errorf("cipher[%d] = %#x, want %#x", i, h.Ciphers[i], want)
		}
	}
	if len(h.Curves) != 2 || h.Curves[0] != 29 || h.Curves[1] != 23 {
		t.Errorf("curves = %v, want [29 23]", h.Curves)
	}
	if len(h.PointFormats) != 1 || h.PointFormats[0] != 0 {
		t.Errorf("point formats = %v, want [0]", h.PointFormats)
	}
	var exts []string
	for _, e := range h.Extensions {
		exts = append(exts, strconv.Itoa(int(e)))
	}
	if got, want := strings.Join(exts, "-"), "0-10-11-16-21"; got != want {
		t.Errorf("extensions = %s, want %s", got, want)
	}
	if h.SNI != "test.example" {
		t.Errorf("SNI = %q, want test.example", h.SNI)
	}
	if len(h.ALPN) != 2 || h.ALPN[0] != "h2" || h.ALPN[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", h.ALPN)
	}
}

func TestJA3(t *testing.T) {
	h := ParseClientHello(buildClientHello(t))
	if h == nil {
		t.Fatal("parse returned nil")
	}
	wantStr := "771,4865-4866-49195,29-23,0,0-10-11-16-21"
	sum := sha1.Sum([]byte(wantStr))
	if got, want := h.JA3(), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("JA3 = %s, want sha1(%q) = %s", got, wantStr, want)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if ParseClientHello([]byte("GET / HTTP/1.1\r\n\r\n")) != nil {
		t.Error("plain HTTP should not parse as ClientHello")
	}
	if ParseClientHello(nil) != nil {
		t.Error("nil should not parse")
	}
}
