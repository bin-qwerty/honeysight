package export

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/honeysight/honeysight/internal/core"
)

func ev(ip, action, ua string, score int, cats ...string) core.Event {
	e := core.NewEvent("http", ip, action)
	e.Timestamp = time.Now().UTC().Add(-time.Minute)
	e.Details["user_agent"] = ua
	e.Enrich(score, cats)
	return e
}

func TestBuildBundle(t *testing.T) {
	e1 := ev("1.2.3.4", "request", "sqlmap/1.8", 40, "sql-injection")
	e2 := ev("1.2.3.4", "cmd", "", 85, "command-injection", "sql-injection")
	e3 := ev("5.6.7.8", "login", "Mozilla/5.0", 0)
	e1.CanaryID = "canary-abc"
	e1.Fingerprint = "29252271fdf7827f083210093b284aee9436de6b"
	e1.Timestamp = e1.Timestamp.Add(-time.Hour) // first seen

	b := BuildBundle([]core.Event{e1, e2, e3})
	if b.Type != "bundle" || b.SpecVersion != "2.1" {
		t.Fatalf("bundle = %s/%s", b.Type, b.SpecVersion)
	}
	if !strings.HasPrefix(b.ID, "bundle:") {
		t.Errorf("bundle id = %q", b.ID)
	}

	// 2 indicators + 1 tool + 1 report
	var indicators, tools, reports int
	for _, o := range b.Objects {
		raw, _ := json.Marshal(o)
		var head struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		_ = json.Unmarshal(raw, &head)
		switch head.Type {
		case "indicator":
			indicators++
			var ind struct {
				Pattern    string   `json:"pattern"`
				Labels     []string `json:"labels"`
				Confidence int      `json:"confidence"`
				Extra      struct {
					Events       int      `json:"events"`
					Protocols    []string `json:"protocols"`
					Actions      []string `json:"actions"`
					Canaries     []string `json:"canaries"`
					Fingerprints []string `json:"fingerprints"`
					Severity     string   `json:"severity"`
				} `json:"x_honeysight"`
			}
			_ = json.Unmarshal(raw, &ind)
			if ind.Extra.Events == 2 {
				if ind.Pattern != "[ipv4-addr:value = '1.2.3.4']" {
					t.Errorf("pattern = %q", ind.Pattern)
				}
				// the 1.2.3.4 indicator
				if ind.Confidence != 85 {
					t.Errorf("merged score = %d, want 85 (max)", ind.Confidence)
				}
				if len(ind.Labels) != 2 {
					t.Errorf("labels = %v, want 2 unique", ind.Labels)
				}
				if len(ind.Extra.Canaries) != 1 || ind.Extra.Canaries[0] != "canary-abc" {
					t.Errorf("canaries = %v", ind.Extra.Canaries)
				}
				if len(ind.Extra.Fingerprints) != 1 {
					t.Errorf("fingerprints = %v", ind.Extra.Fingerprints)
				}
				if ind.Extra.Severity != core.SevCritical {
					t.Errorf("severity = %q", ind.Extra.Severity)
				}
			}
		case "tool":
			tools++
			var tl struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &tl)
			if tl.Name != "sqlmap" {
				t.Errorf("tool name = %q", tl.Name)
			}
		case "report":
			reports++
		}
	}
	if indicators != 2 || tools != 1 || reports != 1 {
		t.Errorf("objects = %d indicators, %d tools, %d reports; want 2/1/1", indicators, tools, reports)
	}
}

func TestBuildBundleIPv6(t *testing.T) {
	e := ev("2001:db8::1", "request", "", 0)
	b := BuildBundle([]core.Event{e})
	raw, _ := json.Marshal(b.Objects[0])
	if !strings.Contains(string(raw), "[ipv6-addr:value = '2001:db8::1']") {
		t.Errorf("ipv6 pattern missing: %s", raw)
	}
}

func TestBuildBundleStableShape(t *testing.T) {
	// Bundle must be JSON-serializable with the STIX field names intact.
	b := BuildBundle([]core.Event{ev("9.9.9.9", "banner", "", 0)})
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"type", "id", "spec_version", "objects"} {
		if _, ok := m[k]; !ok {
			t.Errorf("bundle missing key %q", k)
		}
	}
	_ = fmt.Sprintf
}
