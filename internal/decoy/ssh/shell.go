package ssh

import (
	"bufio"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/honeysight/honeysight/internal/canary"
	"github.com/honeysight/honeysight/internal/core"
	"github.com/honeysight/honeysight/internal/detect"
	"github.com/honeysight/honeysight/internal/track"
)

// Machine persona of the fake box (must match the web decoy's company).
const (
	fakeHostname = "northwind-app01"
	fakeUptime   = " 09:41:22 up 14 days,  3:22,  2 users,  load average: 0.15, 0.11, 0.09"
)

// session is one authenticated SSH session (fake shell).
type session struct {
	log    *slog.Logger
	ip     string
	port   int
	user   string
	set    *canary.Set
	client string // SSH client version, e.g. SSH-2.0-OpenSSH_8.9p1

	bus     *core.Bus
	engine  *detect.Engine
	tracker *track.Tracker
	tarpit  time.Duration
	term    string
}

func newSession(log *slog.Logger, ip string, port int, user string, set *canary.Set, client string, bus *core.Bus, engine *detect.Engine, tracker *track.Tracker, tarpit time.Duration) *session {
	return &session{log: log, ip: ip, port: port, user: user, set: set, client: client, bus: bus, engine: engine, tracker: tracker, tarpit: tarpit, term: "xterm-256color"}
}

func (s *session) home() string {
	if s.user == "root" {
		return "/root"
	}
	return "/home/" + s.user
}

func (s *session) prompt() string {
	if s.user == "root" {
		return fmt.Sprintf("root@%s:~$ ", fakeHostname)
	}
	return fmt.Sprintf("%s@%s:~$ ", s.user, fakeHostname)
}

// runInteractive serves an interactive shell until EOF or "exit".
func (s *session) runInteractive(ch gossh.Channel) {
	defer ch.Close()
	w := bufio.NewWriter(ch)
	_, _ = w.WriteString(s.prompt())
	_ = w.Flush()

	r := bufio.NewReader(ch)
	var line strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return
		}
		switch b {
		case '\n':
			cmd := strings.TrimSpace(line.String())
			line.Reset()
			if cmd != "" {
				if cmd == "exit" || cmd == "logout" {
					_, _ = w.WriteString("logout\n")
					_ = w.Flush()
					sendExitStatus(ch, 0)
					return
				}
				out := s.exec(cmd)
				_, _ = w.WriteString(out)
				_, _ = w.WriteString(s.prompt())
				_ = w.Flush()
			}
		case '\r', 127, 8: // CR, DEL, backspace — echo handling is the client's job
		default:
			line.WriteByte(b)
		}
	}
}

// runOnce executes a single command (exec request) and closes the channel.
func (s *session) runOnce(ch gossh.Channel, cmd string) {
	defer ch.Close()
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return
	}
	_, _ = ch.Write([]byte(s.exec(cmd)))
	sendExitStatus(ch, 0)
}

// exec runs a command through the fake interpreter and publishes the
// interaction. Tarpit: quarantined sources get every answer slowed down.
func (s *session) exec(cmd string) string {
	if s.tracker != nil && s.tracker.IsBlocked(s.ip) {
		time.Sleep(s.tarpit)
	}

	ev := core.NewEvent("ssh", s.ip, "cmd")
	ev.SourcePort = s.port
	ev.Fingerprint = s.client
	ev.Details["user"] = s.user
	ev.Details["command"] = cmd
	if s.set != nil {
		ev.CanaryID = s.set.ID
	}
	det := s.engine.Analyze(detect.Fields{Body: cmd})
	ev.Enrich(det.Score, det.Categories)
	s.bus.Publish(ev)

	if det.IsMalicious() {
		s.log.Warn("ssh cmd", "id", ev.ID, "ip", s.ip, "score", det.Score,
			"severity", ev.Severity, "categories", strings.Join(det.Categories, ","), "cmd", cmd)
	}
	return s.runCmd(cmd)
}

// runCmd is the fake shell brain. Pure w.r.t. the network; all "files"
// are fabricated and seeded with this source's canary tokens.
// It understands minimal shell syntax: pipelines (;, &&, ||, |) — the
// detection engine sees the raw full command either way.
func (s *session) runCmd(cmd string) string {
	if !strings.ContainsAny(cmd, ";&") && strings.Contains(cmd, "|") {
		// simple pipeline: only the last stage's output reaches the terminal
		return s.runSimple(strings.Fields(cmd[strings.LastIndex(cmd, "|"):]))
	}
	var out string
	for _, p := range splitShell(cmd) {
		if f := strings.Fields(p); len(f) > 0 {
			out += s.runSimple(f)
		}
	}
	return out
}

// splitShell splits on ; && || (but not on | inside a pipeline).
func splitShell(cmd string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(cmd); {
		switch {
		case strings.HasPrefix(cmd[i:], "&&") || strings.HasPrefix(cmd[i:], "||"):
			parts = append(parts, cur.String())
			cur.Reset()
			i += 2
		case cmd[i] == ';':
			parts = append(parts, cur.String())
			cur.Reset()
			i++
		default:
			cur.WriteByte(cmd[i])
			i++
		}
	}
	parts = append(parts, cur.String())
	return parts
}

// runSimple executes a single (already split) command.
func (s *session) runSimple(fields []string) string {
	c := fields[0]
	rest := fields[1:]

	switch c {
	case "whoami":
		return s.user + "\n"
	case "id":
		return s.idOutput() + "\n"
	case "pwd":
		return s.home() + "\n"
	case "hostname":
		return fakeHostname + "\n"
	case "uname":
		return "Linux " + fakeHostname + " 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 12 13:07:14 UTC 2024 x86_64 GNU/Linux\n"
	case "uptime":
		return fakeUptime + "\n"
	case "clear":
		return "\x1b[2J\x1b[H"
	case "history":
		return s.historyContent()
	case "env":
		return s.envContent()
	case "ls":
		return s.lsOutput(rest)
	case "cat":
		return s.catOutput(rest)
	case "ps":
		return s.psOutput()
	case "netstat", "ss":
		return s.netstatOutput()
	case "ifconfig", "ip":
		return s.ifconfigOutput()
	case "df":
		return "Filesystem      Size  Used Avail Use% Mounted on\n" +
			"/dev/nvme0n1p1  984G  213G  720G  23% /\n" +
			"tmpfs              32G  1.2G   31G   4% /dev/shm\n"
	case "free":
		return "               total        used        free      shared  buff/cache   available\n" +
			"Mem:          65484712     8123456    49123456      123456    12345672    55678901\n" +
			"Swap:             0           0           0\n"
	case "last":
		return "relogin   pts/0      10.0.3.77      " + s.today() + " 08:57   still logged in\n" +
			"j.morgan  pts/0      10.0.3.77      " + s.today() + " 08:55 - 09:12 (00:17)\n" +
			"deploy    pts/1      10.0.3.52      " + s.yesterday() + " 21:40 - 21:55 (00:15)\n"
	case "":
		return ""
	default:
		return fmt.Sprintf("bash: %s: command not found\n", c)
	}
}

func (s *session) idOutput() string {
	if s.user == "root" {
		return "uid=0(root) gid=0(root) groups=0(root)"
	}
	return fmt.Sprintf("uid=1001(%s) gid=1001(%s) groups=1001(%s),27(sudo)", s.user, s.user, s.user)
}

func (s *session) today() string { return time.Now().Format("Mon Jan  2 15:04") }
func (s *session) yesterday() string {
	return time.Now().Add(-24 * time.Hour).Format("Mon Jan  2 15:04")
}

// --- file contents (all fabricated, canary-seeded) -----------------------

func (s *session) v(kind canary.Kind, fallback string) string {
	if s.set != nil {
		if val := s.set.Value(kind); val != "" {
			return val
		}
	}
	return fallback
}

func (s *session) envContent() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HOSTNAME=%s\n", fakeHostname)
	fmt.Fprintf(&b, "USER=%s\n", s.user)
	fmt.Fprintf(&b, "HOME=%s\n", s.home())
	b.WriteString("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	b.WriteString("PWD=" + s.home() + "\n")
	b.WriteString("SHELL=/bin/bash\n")
	b.WriteString("TERM=" + s.term + "\n")
	fmt.Fprintf(&b, "DB_HOST=%s\n", s.v(canary.KindInternalIP, "10.0.3.51"))
	fmt.Fprintf(&b, "DB_PASSWORD=%s\n", s.v(canary.KindDBPassword, "Nw-0000-demo!0000"))
	fmt.Fprintf(&b, "NOTES_API_KEY=%s\n", s.v(canary.KindAPIKey, "nk_live_000000000000000000000000"))
	fmt.Fprintf(&b, "AWS_ACCESS_KEY_ID=%s\n", s.v(canary.KindAWSAccess, "AKIA0000000000000000"))
	fmt.Fprintf(&b, "AWS_SECRET_ACCESS_KEY=%s\n", s.v(canary.KindAWSSecret, strings.Repeat("x", 40)))
	return b.String()
}

func (s *session) bashHistory() string {
	var b strings.Builder
	b.WriteString("cat /var/log/postgresql/postgresql-14-main.log\n")
	fmt.Fprintf(&b, "PGPASSWORD='%s' psql -h %s -U northwind -d northwind -c 'select count(*) from sessions'\n",
		s.v(canary.KindDBPassword, "Nw-0000-demo!0000"),
		s.v(canary.KindInternalIP, "10.0.3.51"))
	b.WriteString("curl -s http://10.0.3.77:8080/api/health\n")
	b.WriteString("sudo systemctl restart northwind-api\n")
	b.WriteString("aws s3 ls s3://northwind-backups\n")
	fmt.Fprintf(&b, "scp backup_db.sql.gz %s@10.0.3.77:/backups/\n", s.v(canary.KindUsername, "j.morgan"))
	b.WriteString("vim notes.txt\n")
	return b.String()
}

func (s *session) historyContent() string {
	var b strings.Builder
	lines := strings.Split(strings.TrimRight(s.bashHistory(), "\n"), "\n")
	for i, l := range lines {
		fmt.Fprintf(&b, "%4d  %s\n", 240+i, l)
	}
	return b.String()
}

func (s *session) lsOutput(args []string) string {
	long := false
	path := ""
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "l") {
				long = true
			}
		} else {
			path = a
		}
	}
	if path == "" || path == "." || path == s.home() {
		if !long {
			return ".bash_history  .env  .ssh  backup_db.sql.gz  deploy.sh  notes.txt\n"
		}
		return "total 48\n" +
			"drwx------  2 root root   4096 Mar 12 09:14 .ssh\n" +
			"-rw-r--r--  1 root root    812 Mar  2 14:03 .env\n" +
			"-rw-r--r--  1 root root   1204 Mar  2 14:07 .bash_history\n" +
			"-rw-r--r--  1 root root 204800 Mar 12 09:02 backup_db.sql.gz\n" +
			"-rwxr-xr-x  1 root root    940 Jan 28 10:22 deploy.sh\n" +
			"-rw-r--r--  1 root root    388 Feb 15 08:51 notes.txt\n"
	}
	switch path {
	case "/":
		return "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n"
	case "/etc":
		return "adduser  apt  bash.bashrc  cron.d  cron.daily  environment  fstab  group  hosts  issue  kernel  passwd  profile  rc.local  services  ssh  shadow\n"
	case "/var/log":
		return "alternatives.log  apt  auth.log  boot.log  dpkg.log  faillog  kern.log  lastlog  postgresql  wtmp\n"
	case "/opt":
		return "northwind\n"
	case "/home":
		return "deploy  j.morgan\n"
	default:
		return "ls: cannot access '" + path + "': No such file or directory\n"
	}
}

func (s *session) catOutput(args []string) string {
	if len(args) == 0 {
		return "cat: missing operand\nTry 'cat --help' for more information.\n"
	}
	out := ""
	for _, p := range args {
		out += s.catFile(p)
	}
	return out
}

func (s *session) catFile(p string) string {
	home := s.home()
	p = strings.TrimPrefix(p, "~/")
	if !strings.HasPrefix(p, "/") {
		p = home + "/" + p
	}
	p = strings.TrimSuffix(p, "/")

	switch p {
	case home + "/.env":
		return s.envContent()
	case home + "/deploy.sh":
		var b strings.Builder
		b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n")
		fmt.Fprintf(&b, "export NOTES_API_KEY=%s\n", s.v(canary.KindAPIKey, "nk_live_000000000000000000000000"))
		fmt.Fprintf(&b, "ssh deploy@%s \"sudo systemctl restart northwind-api\"\n", s.v(canary.KindInternalIP, "10.0.3.51"))
		b.WriteString("curl -fsSL https://ci.northwind.example/artifacts/northwind-api.tar.gz | tar -xz -C /opt/northwind\n")
		return b.String()
	case home + "/notes.txt":
		var b strings.Builder
		fmt.Fprintf(&b, "- %s's DB password is in .env: %s\n", s.v(canary.KindUsername, "j.morgan"), s.v(canary.KindDBPassword, "Nw-0000-demo!0000"))
		b.WriteString("- staging box: 10.0.3.77 (same creds as prod, do not mix up)\n")
		b.WriteString("- redis on 10.0.3.52 has NO password — billing uses it\n")
		return b.String()
	case home + "/.bash_history", home + "/.bash_history.1":
		return s.bashHistory()
	case "/etc/passwd":
		return "root:x:0:0:root:/root:/bin/bash\n" +
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
			"sys:x:2:2:sys:/dev:/usr/sbin/nologin\n" +
			"sync:x:4:65534:sync:/bin:/bin/sync\n" +
			"postgres:x:105:112:PostgreSQL administrator,,,,:/var/lib/postgresql:/bin/bash\n" +
			fmt.Sprintf("%s:x:1001:1001::/home/%s:/bin/bash\n", s.v(canary.KindUsername, "j.morgan"), s.v(canary.KindUsername, "j.morgan")) +
			"deploy:x:1002:1002::/home/deploy:/bin/bash\n"
	case "/etc/hosts":
		return "127.0.0.1\tlocalhost\n" +
			fmt.Sprintf("%s\t%s\n", s.v(canary.KindInternalIP, "10.0.3.51"), fakeHostname) +
			"10.0.3.52\tredis-cache\n" +
			"10.0.3.77\tstaging\n"
	case "/etc/shadow":
		if s.user != "root" {
			return "cat: /etc/shadow: Permission denied\n"
		}
		return "root:$6$rZ5m3x0F$9kQ2mH7vL1pX4nB8cV0wY6tR3aE5dG1jK9sU2iO4fA7hD3lN6qW8zM1xP5bT0rY4:19423:0:99999:7:::\n" +
			fmt.Sprintf("%s:$6$kQ8vN2m$7wR4tY6uI9oP3aE5dF1gH2jK4lZ8xC0vB9nM1qW3eR5tY7uI9oP2aE4dF6gH8jK0:19511:0:99999:7:::\n", s.v(canary.KindUsername, "j.morgan"))
	case home + "/.ssh/authorized_keys":
		return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNorthwindDeployKey0000000000000000000 deploy@northwind-ci\n"
	case home + "/backup_db.sql.gz":
		return "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\n" + "(binary data)\n"
	default:
		return fmt.Sprintf("cat: %s: No such file or directory\n", p)
	}
}

func (s *session) psOutput() string {
	var b strings.Builder
	b.WriteString("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
	b.WriteString("root           1  0.0  0.1 167644 12344 ?        Ss   Mar12   0:03 /sbin/init\n")
	b.WriteString("root         812  0.0  0.2  19876  8901 ?        Ss   Mar12   0:00 sshd: /usr/sbin/sshd -D [listener]\n")
	b.WriteString("postgres    1204  0.3  4.2 2183456 2765432 ?     Ssl  Mar12  42:11 /usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main\n")
	b.WriteString("redis       1350  0.5  1.1  76543  73456 ?       Ssl  Mar12  61:02 redis-server *:6379\n")
	b.WriteString(fmt.Sprintf("%s       %d  1.2  8.4 12893456 5567890 pts/0  Sl+  08:57   1:22 node /opt/northwind/api/server.js\n", s.user, 4321))
	b.WriteString(fmt.Sprintf("%s       %d  0.0  0.0   3952  3210 pts/0    Ss   09:41   0:00 bash\n", s.user, 4502))
	return b.String()
}

func (s *session) netstatOutput() string {
	var b strings.Builder
	b.WriteString("Active Internet connections (only servers)\n")
	b.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n")
	b.WriteString("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n")
	b.WriteString("tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN\n")
	b.WriteString(fmt.Sprintf("tcp        0      0 %s:6379          0.0.0.0:*               LISTEN\n", s.v(canary.KindInternalIP, "10.0.3.51")))
	b.WriteString(fmt.Sprintf("tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN\n"))
	return b.String()
}

func (s *session) ifconfigOutput() string {
	ip := s.v(canary.KindInternalIP, "10.0.3.51")
	var b strings.Builder
	b.WriteString("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n")
	fmt.Fprintf(&b, "        inet %s  netmask 255.255.255.0  broadcast 10.0.3.255\n", ip)
	b.WriteString("        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)\n")
	b.WriteString("        RX packets 8923451  bytes 9123456789  (9.1 GiB)\n")
	b.WriteString("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n")
	b.WriteString("        inet 127.0.0.1  netmask 255.0.0.0\n")
	return b.String()
}
