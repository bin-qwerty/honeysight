package fingerprint

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	kpem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	cert, err := tls.X509KeyPair(cb, kpem)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestTlsServeEndToEnd runs the real capture+handshake+HTTP path against a
// real TLS client.
func TestTlsServeEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}}

	var mu sync.Mutex
	var gotHello *Hello
	var gotPath string
	factory := func(h *Hello) http.Handler {
		return Decorate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotHello = HelloFrom(r)
			gotPath = r.URL.Path
			mu.Unlock()
			fmt.Fprintln(w, "hello over tls")
		}), h)
	}
	go Serve(ln, cfg, factory)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	req := "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := io.ReadAll(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response from TLS listener")
	}
	if want := "hello over tls"; !contains(string(resp), want) {
		t.Fatalf("response = %q, want to contain %q", resp, want)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		h, p := gotHello, gotPath
		mu.Unlock()
		if h != nil {
			if p != "/probe" {
				t.Errorf("path = %q, want /probe", p)
			}
			if h.JA3() == "" {
				t.Error("JA3 empty")
			}
			if len(h.Ciphers) == 0 {
				t.Error("no ciphers captured")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("handler never ran with a captured hello")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

var _ = http.StatusOK
