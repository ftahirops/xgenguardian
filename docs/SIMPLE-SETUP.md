# Simple Setup — Two Public Ports

This is the minimal way to use the system.

## What's exposed to the internet (you only)

| Port | Protocol | What you do with it |
|---|---|---|
| **53** | UDP + TCP | Set this as your DNS server. That's it. Any device, any OS. |
| **13000** | TCP / plain HTTP | The web dashboard at `http://135.181.79.27:13000/admin/login` |

Both ports are locked to `95.211.19.203` by the host firewall. No one else can reach them.

## What's NOT exposed

All the other XGG services are bound to `127.0.0.1` — they only listen on the loopback interface. The internet cannot see them at all, firewall or not:

- verdict-api on `127.0.0.1:18080`
- portal-api on `127.0.0.1:18081`
- sandbox-render on `127.0.0.1:8002`
- visual-match on `127.0.0.1:8003`
- Postgres, Redis, MinIO

The dashboard at :13000 proxies to those internal services for you.

## One-time setup (on this server)

```bash
cd /home/xgenguardian/code
make bringup                                    # Docker + Postgres + Redis + MinIO + migrations
export ADMIN_PASSWORD="$(openssl rand -base64 18)"
echo "Save this password somewhere: $ADMIN_PASSWORD"

# resolver needs CAP_NET_BIND_SERVICE to bind to UDP/TCP 53.
# `make dev-up` runs each service under your user; we use authbind / capabilities.
# Easiest for first run: run resolver as root in its own terminal.
sudo setcap 'cap_net_bind_service=+ep' "$(go env GOPATH)/bin/resolver" 2>/dev/null || true

make dev-up                                     # starts every service
```

## On your laptop

### Step 1 — Set your DNS to the server's public IP

| OS | How |
|---|---|
| **macOS** | System Settings → Network → your interface → Details → DNS → DNS Servers → add `135.181.79.27` (and remove other entries while you test) |
| **Windows 11** | Settings → Network & Internet → your adapter → DNS server assignment → Manual → IPv4 → Preferred DNS: `135.181.79.27` |
| **Linux (systemd-resolved)** | `sudo resolvectl dns <iface> 135.181.79.27` |
| **Phone** | Wi-Fi settings → your network → Configure DNS → Manual → `135.181.79.27` |
| **Router (whole home)** | LAN/DHCP settings → DNS servers → primary `135.181.79.27` |

Verify it's working:
```bash
dig @135.181.79.27 example.com +short
# or on Windows:  nslookup example.com 135.181.79.27
```

You should get an IP back within 1 second.

### Step 2 — Open the dashboard

`http://135.181.79.27:13000/admin/login`

Type the `ADMIN_PASSWORD` from setup. You're in.

### Step 3 — Test

Open any URL in any browser. Look at the dashboard:

| Tab | What it shows |
|---|---|
| `/admin`          | 24-hour overview, sparkline, top blocked |
| `/admin/queries`  | Every DNS lookup, with verdict + cache hit + latency. Filter by domain / verdict. |
| `/admin/verdicts` | Per-URL deep analysis (screenshots, brand match, signals) |
| `/live`           | Real-time stream of verdicts as they happen |

Or push URLs directly through the verdict pipeline (skips the DNS layer, runs the full sandbox + visual analysis):
```bash
ssh root@135.181.79.27 -p 22000 \
  'curl -s http://127.0.0.1:18080/v1/check \
     -H "content-type: application/json" \
     -d "{\"url\":\"https://paypa1-secure.tk/login\"}" | jq .'
```

Then refresh `/admin/verdicts` to see it.

## When you're done testing

To restore your laptop's normal DNS, change the DNS server back to automatic / your old setting.

To shut down the stack on the server:
```bash
make dev-down
```

The firewall rules persist across reboots and shutdowns — that's correct, you want to stay locked down.

## Undo the firewall

If you ever want to drop the IP lockdown:
```bash
sudo iptables-restore < /tmp/iptables-before-xgg-<TIMESTAMP>.rules
sudo netfilter-persistent save
```

The backup file path is printed every time you run `./scripts/lockdown.sh`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `dig @135.181.79.27` hangs | resolver not running, or you're not on `95.211.19.203` |
| Dashboard "this site can't be reached" | portal not running, or wrong IP. From the server: `curl -s http://localhost:13000` to confirm |
| Dashboard loads but admin shows 403 | `ADMIN_PASSWORD` not exported in the verdict-api / portal-api shells |
| DNS works for `google.com` but every site says "BLOCKED" | brand registry isn't seeded yet — run `make seed-brands` |
| `make dev-up` complains resolver can't bind :53 | needs root or `setcap`. See setup step above. |
