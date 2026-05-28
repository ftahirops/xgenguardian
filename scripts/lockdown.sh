#!/usr/bin/env bash
# XGenGuardian — IP lockdown.
#
# Restricts the XGG ports (and nginx :80/:443 as requested) so only one IP
# can reach them. Everything else on the host is left untouched.
#
# Designed to be safe to re-run: it removes its own previous rules before
# re-applying, so it's idempotent.
#
# Undo: see /tmp/iptables-before-xgg-<timestamp>.rules saved on first run.
set -euo pipefail

# --- configuration ----------------------------------------------------------
# Multiple IPs allowed in. Pass as comma-separated via ALLOWED_IPS.
ALLOWED_IPS="${ALLOWED_IPS:-95.211.19.203,95.211.19.202,135.181.79.27,127.0.0.1}"
SSH_PORT="${SSH_PORT:-22000}"
# Public XGG ports (TCP). Everything else (verdict-api, portal-api, sandbox,
# visual-match) binds to 127.0.0.1 so no firewall rule is needed for them.
XGG_TCP_PORTS=(13000)            # dashboard (plain HTTP)
# Public DNS port — both TCP and UDP need locking.
XGG_DNS_PORT="${XGG_DNS_PORT:-53}"
COMMENT_TAG="xgg-lockdown"
# ----------------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
  echo "This script needs root. Re-run with sudo." >&2
  exit 1
fi

stamp=$(date +%s)
backup="/tmp/iptables-before-xgg-${stamp}.rules"
backup6="/tmp/ip6tables-before-xgg-${stamp}.rules"

echo "▸ Backing up current rules to:"
echo "    $backup"
echo "    $backup6"
iptables-save  > "$backup"
ip6tables-save > "$backup6" 2>/dev/null || true

# --- clean any rules left by a previous run of this script ------------------
echo "▸ Removing prior xgg-lockdown rules (if any)"
remove_tagged() {
  local cmd="$1"
  local rules
  rules=$($cmd -S 2>/dev/null | grep -- "--comment $COMMENT_TAG" || true)
  [ -z "$rules" ] && return 0
  while IFS= read -r r; do
    [ -z "$r" ] && continue
    # turn -A into -D, eval to expand quotes correctly
    local del="${r/-A /-D }"
    # shellcheck disable=SC2086
    $cmd $del 2>/dev/null || true
  done <<< "$rules"
}
remove_tagged iptables
remove_tagged ip6tables

# --- safety first: explicit SSH allow for every allowed IP -----------------
IFS=',' read -ra ALLOWED_ARR <<< "$ALLOWED_IPS"
for ip in "${ALLOWED_ARR[@]}"; do
  ip="${ip// /}"
  [ -z "$ip" ] && continue
  echo "▸ Belt-and-suspenders: ACCEPT SSH from $ip -> :$SSH_PORT"
  iptables -I INPUT 1 -p tcp -s "$ip" --dport "$SSH_PORT" -j ACCEPT \
    -m comment --comment $COMMENT_TAG
done

# --- per-port lockdown ------------------------------------------------------
lock_tcp() {
  local port="$1"
  echo "▸ Lock TCP :$port -> only allowed IPs"
  for ip in "${ALLOWED_ARR[@]}"; do
    ip="${ip// /}"; [ -z "$ip" ] && continue
    iptables -A INPUT -p tcp -s "$ip" --dport "$port" -j ACCEPT \
      -m comment --comment $COMMENT_TAG
  done
  # Always allow loopback for this port (lo iface). Belt-and-suspenders in
  # case 127.0.0.1 wasn't in the allowed list.
  iptables -A INPUT -i lo -p tcp --dport "$port" -j ACCEPT \
    -m comment --comment $COMMENT_TAG
  iptables -A INPUT -p tcp --dport "$port" -j DROP \
    -m comment --comment $COMMENT_TAG
  ip6tables -A INPUT -p tcp --dport "$port" -j DROP \
    -m comment --comment $COMMENT_TAG 2>/dev/null || true
}
lock_udp() {
  local port="$1"
  echo "▸ Lock UDP :$port -> only allowed IPs"
  for ip in "${ALLOWED_ARR[@]}"; do
    ip="${ip// /}"; [ -z "$ip" ] && continue
    iptables -A INPUT -p udp -s "$ip" --dport "$port" -j ACCEPT \
      -m comment --comment $COMMENT_TAG
  done
  iptables -A INPUT -i lo -p udp --dport "$port" -j ACCEPT \
    -m comment --comment $COMMENT_TAG
  iptables -A INPUT -p udp --dport "$port" -j DROP \
    -m comment --comment $COMMENT_TAG
  ip6tables -A INPUT -p udp --dport "$port" -j DROP \
    -m comment --comment $COMMENT_TAG 2>/dev/null || true
}

# Classic DNS — UDP and TCP both
lock_udp "$XGG_DNS_PORT"
lock_tcp "$XGG_DNS_PORT"

# Web dashboard (and any other TCP-only XGG public services)
for p in "${XGG_TCP_PORTS[@]}"; do lock_tcp "$p"; done

# --- persist ----------------------------------------------------------------
echo "▸ Persisting rules across reboots"
export DEBIAN_FRONTEND=noninteractive
echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt-get install -y iptables-persistent >/dev/null
netfilter-persistent save >/dev/null

# --- show result ------------------------------------------------------------
echo
echo "▸ Active xgg-lockdown rules (filter / INPUT):"
iptables -nvL INPUT --line-numbers | grep -E "xgg-lockdown|^Chain|^num" || true
echo
echo "✓ Lockdown applied."
echo
echo "Locked ports (only $ALLOWED_IPS can reach them):"
echo "    UDP/$XGG_DNS_PORT, TCP/$XGG_DNS_PORT  (classic DNS)"
printf "    TCP/%s\n" "${XGG_TCP_PORTS[@]}"
echo
echo "Undo:"
echo "    sudo iptables-restore  < $backup"
echo "    sudo ip6tables-restore < $backup6"
echo "    sudo netfilter-persistent save"
