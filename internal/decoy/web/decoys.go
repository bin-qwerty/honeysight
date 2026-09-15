package web

import "strings"

// All content below is fabricated. It exists to make the surface look like a
// real, slightly vulnerable target so an attacker keeps interacting — every
// interaction is captured and scored.

const landingPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Northwind Internal Portal</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,Arial,sans-serif;margin:0;background:#0f1116;
color:#e8eaed}header{padding:22px 32px;border-bottom:1px solid #23262d}
main{max-width:720px;margin:64px auto;padding:0 24px}a{color:#ffb703}
.card{background:#161922;border:1px solid #23262d;border-radius:10px;
padding:24px;margin-top:20px}code{color:#9ad}</style>
</head>
<body><header><strong>Northwind Industries</strong> · Internal Portal</header>
<main><h1>Employee Services</h1>
<p>Welcome. Please sign in to access internal tooling.</p>
<div class="card"><p><a href="/admin">Admin console</a> ·
<a href="/wp-login.php">Legacy CMS</a> ·
<a href="/phpmyadmin/">Database</a></p>
<p><small>Server: Apache/2.4.49 (Ubuntu) · PHP/8.1.2 · nginx/1.24</small></p></div>
</main></body></html>`

// fakeEnv looks like a leaked application config. Every value is fake.
const fakeEnv = `APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:a2V5LW5vdC1yZWFsLW9ubHktZm9yLWRlY2VwdGlvbg==
DB_HOST=10.0.3.15
DB_PORT=3306
DB_DATABASE=crm_prod
DB_USERNAME=app_rw
DB_PASSWORD=Hn5-fake-9f3a7c
REDIS_HOST=10.0.3.16
REDIS_PORT=6379
REDIS_PASSWORD=Hn5-fake-rd5b21
AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKEFAKE
AWS_SECRET_ACCESS_KEY=FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE/
SMTP_HOST=smtp.internal.northwind.example
`

const fakeGitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = git@git.northwind.example:platform/portal.git
[user]
	email = ops@northwind.example
`

const fakeLogin = `<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in — Northwind IDaaS</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1116;color:#e8eaed;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#161922;border:1px solid #23262d;border-radius:10px;padding:28px;
width:320px}input{width:100%;box-sizing:border-box;margin:6px 0 14px;padding:8px;
background:#0f1116;border:1px solid #23262d;border-radius:6px;color:#e8eaed}
button{width:100%;padding:9px;background:#2563eb;border:0;border-radius:6px;
color:#fff;font-weight:600}small{color:#6b7280}</style></head>
<body><form method="post" action="/admin/login">
<h3 style="margin-top:0">Northwind IDaaS</h3>
<label>Username <input name="user"></label>
<label>Password <input type="password" name="pass"></label>
<button type="submit">Sign in</button>
<small>IDaaS 3.2.1 · SSO available for employees</small>
</form></body></html>`

// fakeMetadata mimics the cloud instance metadata service (169.254.169.254)
// that cloud workloads query for credentials.
const fakeMetadata = `dns-name
hostname
instance-id
local-hostname
local-ipv4
metrics
profile
public-ipv4
public-keys
reservation-id
security-groups
`

type bait struct {
	status      int
	contentType string
	body        []byte
}

// decoyFor returns bait for a path/host. ok=false means "no specific decoy"
// (the caller serves a generic 404 that was already logged).
func decoyFor(path, host string) (bait, bool) {
	p := strings.ToLower(path)

	// Cloud metadata surface: matched by host or path prefix.
	if host == "169.254.169.254" ||
		strings.HasPrefix(p, "/latest/meta-data") ||
		strings.HasPrefix(p, "/metadata") {
		return bait{200, "text/plain", []byte(fakeMetadata)}, true
	}

	switch p {
	case "/", "/index.html":
		return bait{200, "text/html; charset=utf-8", []byte(landingPage)}, true
	case "/.env":
		return bait{200, "text/plain", []byte(fakeEnv)}, true
	case "/.git/config":
		return bait{200, "text/plain", []byte(fakeGitConfig)}, true
	case "/admin", "/admin/login", "/wp-login.php", "/phpmyadmin", "/phpmyadmin/":
		return bait{200, "text/html; charset=utf-8", []byte(fakeLogin)}, true
	}
	return bait{}, false
}
