package redis

import (
	"fmt"

	"github.com/honeysight/honeysight/internal/canary"
)

// RedisVersion is what INFO reports.
const RedisVersion = "7.2.4"

// keyspace is the fake dataset. The canary-bearing keys make every
// source's data unique, so a later leak is attributable.
type keyspace struct {
	keys   []string
	values map[string]string
}

// newKeyspace builds the fake dataset for one source. set may be nil
// (then static values are used — tests).
func newKeyspace(set *canary.Set) *keyspace {
	val := func(kind canary.Kind, fallback string) string {
		if set != nil {
			if v := set.Value(kind); v != "" {
				return v
			}
		}
		return fallback
	}

	ks := &keyspace{values: map[string]string{
		"northwind:api:secret":            val(canary.KindAPIKey, "nk_live_static00000000000000000000000000"),
		"northwind:db:password":           val(canary.KindDBPassword, "static-db-pass-00000000"),
		"northwind:db:host":               val(canary.KindInternalIP, "10.0.3.198"),
		"northwind:aws:access_key_id":     val(canary.KindAWSAccess, "AKIASTATICACCESSKEY0000"),
		"northwind:aws:secret_access_key": val(canary.KindAWSSecret, "staticstaticstaticstaticstaticstatic00000"),
		"northwind:admin:username":        val(canary.KindUsername, "admin"),
		"northwind:gateway:internal":      val(canary.KindInternalIP, "10.0.3.77"),
		"session:counter":                 "1847",
		"cache:users:1001":                `{"id":1001,"email":"jdoe@northwind.example","role":"user"}`,
		"cache:users:1002":                `{"id":1002,"email":"msmith@northwind.example","role":"admin"}`,
	}}
	for k := range ks.values {
		ks.keys = append(ks.keys, k)
	}
	// Deterministic order for stable replies.
	for i := 0; i < len(ks.keys); i++ {
		for j := i + 1; j < len(ks.keys); j++ {
			if ks.keys[j] < ks.keys[i] {
				ks.keys[i], ks.keys[j] = ks.keys[j], ks.keys[i]
			}
		}
	}
	return ks
}

func (k *keyspace) get(key string) (string, bool) {
	v, ok := k.values[key]
	return v, ok
}

func (k *keyspace) size() int { return len(k.keys) }

// info is a believable INFO output.
func (k *keyspace) info() string {
	return fmt.Sprintf(`# Server
redis_version:%s
redis_git_sha1:00000000
redis_mode:standalone
os:Linux 5.15.0-91-generic x86_64
tcp_port:6379
uptime_in_seconds:912345
uptime_in_days:10
# Clients
connected_clients:7
# Memory
used_memory:10485760
used_memory_human:10.00M
used_memory_peak:12582912
# Persistence
rdb_last_bgsave_status:ok
aof_enabled:0
# Replication
role:master
connected_slaves:0
# Keyspace
db0:keys=%d,expires=4,avg_ttl=3600000
`, RedisVersion, k.size())
}

// configGet is a believable subset of CONFIG GET *.
func configGet() []string {
	return []string{
		"maxmemory", "0",
		"maxmemory-policy", "noeviction",
		"appendonly", "no",
		"save", "3600 1 300 100 60 10000",
		"tcp-keepalive", "300",
		"timeout", "0",
		"bind-address", "0.0.0.0",
		"protected-mode", "no",
		"requirepass", "<set>",
		"dir", "/var/lib/redis",
		"daemonize", "yes",
		"supervised", "systemd",
	}
}
