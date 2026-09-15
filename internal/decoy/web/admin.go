package web

import (
	"html/template"
	"strings"

	"github.com/honeysight/honeysight/internal/canary"
)

// The admin dashboard is the "jackpot" page: it looks like a real internal
// admin console with useful-looking data, and every credential in it is a
// canary token unique to the source IP that fetched it. If any of these
// values later appears in the attacker's environment, the source is proven.

var dashTmpl = template.Must(template.New("dash").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Dashboard — Northwind Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,Arial,sans-serif;margin:0;background:#f5f6f8;
color:#1f2430}header{background:#101828;color:#fff;padding:12px 24px;
display:flex;justify-content:space-between;align-items:center}
nav a{color:#9fb3d1;margin-left:16px;text-decoration:none;font-size:14px}
nav a.on{color:#fff}main{padding:24px;max-width:1080px;margin:0 auto}
h2{font-size:16px;margin:0 0 12px}.grid{display:grid;grid-template-columns:
repeat(4,1fr);gap:12px;margin-bottom:20px}.kpi{background:#fff;
border:1px solid #e4e7ec;border-radius:8px;padding:14px}.kpi b{font-size:20px;
display:block}.kpi span{color:#667085;font-size:12px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid
#e4e7ec;border-radius:8px;font-size:13px}th,td{text-align:left;padding:8px 12px;
border-bottom:1px solid #eef0f3}th{background:#f9fafb;color:#475467;
font-size:12px;text-transform:uppercase;letter-spacing:.03em}
code{background:#eef2f6;padding:2px 6px;border-radius:4px;font-size:12px}
.ok{color:#12b76a;font-weight:600}.warn{color:#f79009;font-weight:600}
.card{background:#fff;border:1px solid #e4e7ec;border-radius:8px;
padding:16px;margin-bottom:20px}.card h3{margin:0 0 10px;font-size:14px}
footer{color:#98a2b3;font-size:12px;padding:16px 24px}</style></head>
<body>
<header><strong>Northwind Admin Console</strong>
<nav><a class="on" href="/admin/dashboard">Dashboard</a>
<a href="/admin/users">Users</a><a href="/admin/servers">Servers</a>
<a href="/admin/databases">Databases</a><a href="/admin/settings">Settings</a></nav></header>
<main>
<div class="grid">
<div class="kpi"><b>1,284</b><span>Active users</span></div>
<div class="kpi"><b>37</b><span>Servers online</span></div>
<div class="kpi"><b>12</b><span>Databases</span></div>
<div class="kpi"><b class="ok">99.97%</b><span>Uptime (30d)</span></div>
</div>

<div class="card"><h3>Recent administrator sign-ins</h3>
<table><tr><th>User</th><th>IP</th><th>Time (UTC)</th><th>Status</th></tr>
<tr><td>{{.AdminUser}}</td><td>10.0.1.24</td><td>2026-09-14 06:12</td><td class="ok">success</td></tr>
<tr><td>a.chen</td><td>10.0.1.31</td><td>2026-09-14 05:47</td><td class="ok">success</td></tr>
<tr><td>svc_backup</td><td>10.0.2.9</td><td>2026-09-13 23:00</td><td class="ok">success</td></tr>
<tr><td>unknown</td><td>203.0.113.7</td><td>2026-09-13 21:14</td><td class="warn">failed (locked)</td></tr>
</table></div>

<div class="card"><h3>Database connections</h3>
<table><tr><th>Name</th><th>Host</th><th>User</th><th>Password</th><th>Status</th></tr>
<tr><td>crm_prod</td><td>10.0.3.15:3306</td><td>app_rw</td><td><code>{{.DBPassword}}</code></td><td class="ok">healthy</td></tr>
<tr><td>crm_repl</td><td>10.0.3.17:3306</td><td>repl</td><td><code>Repl-2026-x9k</code></td><td class="ok">healthy</td></tr>
<tr><td>analytics</td><td>10.0.3.18:5432</td><td>bi_ro</td><td><code>Bi-2026-m4p</code></td><td class="warn">degraded</td></tr>
</table></div>

<div class="card"><h3>Legacy cloud credentials <small style="color:#98a2b3">(migration pending, ticket OPS-2231)</small></h3>
<table><tr><th>Type</th><th>Value</th><th>Region</th></tr>
<tr><td>AWS Access Key ID</td><td><code>{{.AWSAccess}}</code></td><td>us-east-1</td></tr>
<tr><td>AWS Secret Access Key</td><td><code>{{.AWSSecret}}</code></td><td>us-east-1</td></tr>
<tr><td>Internal API key</td><td><code>{{.APIKey}}</code></td><td>—</td></tr>
</table></div>

<div class="card"><h3>Internal services</h3>
<table><tr><th>Service</th><th>Address</th><th>Port</th></tr>
<tr><td>Primary DB</td><td>{{.InternalIP}}</td><td>3306</td></tr>
<tr><td>Git</td><td>git.northwind.example</td><td>22</td></tr>
<tr><td>CI</td><td>jenkins.internal.northwind.example</td><td>8080</td></tr>
<tr><td>Vault</td><td>vault.internal.northwind.example</td><td>8200</td></tr>
<tr><td>Monitoring</td><td>grafana.internal.northwind.example</td><td>3000</td></tr>
</table></div>
</main>
<footer>Northwind Admin Console 4.1.2 · build 2026.08.14 · signed in as {{.AdminUser}}</footer>
</body></html>`))

// renderDashboard renders the admin dashboard with the source's canary set.
func renderDashboard(set *canary.Set) []byte {
	var b strings.Builder
	if err := dashTmpl.Execute(&b, struct {
		AdminUser, DBPassword, AWSAccess, AWSSecret, APIKey, InternalIP string
	}{
		AdminUser:  set.Value(canary.KindUsername),
		DBPassword: set.Value(canary.KindDBPassword),
		AWSAccess:  set.Value(canary.KindAWSAccess),
		AWSSecret:  set.Value(canary.KindAWSSecret),
		APIKey:     set.Value(canary.KindAPIKey),
		InternalIP: set.Value(canary.KindInternalIP),
	}); err != nil {
		return []byte("<html><body><h1>500</h1></body></html>")
	}
	return []byte(b.String())
}
