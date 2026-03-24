#!/bin/sh
set -eu

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

warn() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] WARNING: $*" >&2
}

die() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: $*" >&2
  exit 1
}

# Derive deterministic Curve25519 private key from secret + role
derive_key() {
  role="$1"
  python3 - "$WG_SECRET" "$role" <<'PY'
import base64, hashlib, sys
secret, role = sys.argv[1], sys.argv[2]
seed = hashlib.sha256(f"{secret}|{role}".encode()).digest()
b = bytearray(seed)
b[0] &= 248
b[31] &= 127
b[31] |= 64
print(base64.b64encode(bytes(b)).decode())
PY
}

# Derive preshared key from secret (symmetric, role-independent)
derive_psk() {
  python3 - "$WG_SECRET" <<'PY'
import base64, hashlib, sys
seed = hashlib.sha256(f"{sys.argv[1]}|psk".encode()).digest()
print(base64.b64encode(seed).decode())
PY
}

# Calculate peer address from own WG_ADDRESS
# For /30: toggle between the two usable host IPs
# For larger subnets: server=.1, client=.2
calc_peer_address() {
  my_address="$1" role="$2"
  python3 - "$my_address" "$role" <<'PY'
import ipaddress, sys
iface = ipaddress.ip_interface(sys.argv[1])
network = iface.network
role = sys.argv[2]
hosts = list(network.hosts())
if network.prefixlen >= 30:
    # /30 or /31: toggle between the two host IPs
    my_ip = iface.ip
    if my_ip == hosts[0]:
        print(str(hosts[1]))
    elif my_ip == hosts[1]:
        print(str(hosts[0]))
    else:
        print(f"ERROR: {my_ip} is not a valid host in {network}", file=sys.stderr)
        sys.exit(1)
else:
    # Larger subnets: server=.1, client=.2
    if role == "server":
        print(str(hosts[1]))  # peer is client = .2
    else:
        print(str(hosts[0]))  # peer is server = .1
PY
}

# --- Required variables ---
WG_ROLE="${WG_ROLE:-}"
WG_SECRET="${WG_SECRET:-}"

[ -z "$WG_ROLE" ]   && die "WG_ROLE must be 'server' or 'client'."
[ -z "$WG_SECRET" ] && die "WG_SECRET is not set."

case "$WG_ROLE" in
  server|client) ;;
  *) die "WG_ROLE must be 'server' or 'client' (got: '$WG_ROLE')." ;;
esac

# --- Validate WG_SECRET minimum length ---
if [ "${#WG_SECRET}" -lt 16 ]; then
  warn "WG_SECRET is shorter than 16 characters. Consider using a longer secret for better security."
fi

# --- Optional variables with defaults ---
WG_PORT="${WG_PORT:-51820}"
WG_IFACE="${WG_IFACE:-wg0}"

# Validate WG_PORT
case "$WG_PORT" in
  ''|*[!0-9]*) die "WG_PORT must be a number (got: '$WG_PORT')." ;;
esac
if [ "$WG_PORT" -lt 1 ] || [ "$WG_PORT" -gt 65535 ]; then
  die "WG_PORT must be between 1 and 65535 (got: $WG_PORT)."
fi

# Tunnel IPs: derive peer address dynamically from WG_ADDRESS
if [ "$WG_ROLE" = "server" ]; then
  WG_ADDRESS="${WG_ADDRESS:-10.77.0.1/30}"
else
  WG_ADDRESS="${WG_ADDRESS:-10.77.0.2/30}"
  WG_SERVER_ENDPOINT="${WG_SERVER_ENDPOINT:-}"
  [ -z "$WG_SERVER_ENDPOINT" ] && die "WG_SERVER_ENDPOINT must be set for client role (e.g. 1.2.3.4:51820)."
  # Validate endpoint format (must contain host:port)
  case "$WG_SERVER_ENDPOINT" in
    *:*) ;;
    *) die "WG_SERVER_ENDPOINT must be in host:port format (got: '$WG_SERVER_ENDPOINT')." ;;
  esac
fi

PEER_ADDRESS="$(calc_peer_address "$WG_ADDRESS" "$WG_ROLE")"
log "Local address: $WG_ADDRESS, peer address: $PEER_ADDRESS"

# Default AllowedIPs
if [ "$WG_ROLE" = "client" ]; then
  WG_ALLOWED_IPS="${WG_ALLOWED_IPS:-${PEER_ADDRESS}/32}"
fi

# --- Derive keys ---
log "Deriving keys from shared secret..."
LOCAL_PRIV="$(derive_key "$WG_ROLE")"
LOCAL_PUB="$(printf '%s' "$LOCAL_PRIV" | wg pubkey)"

if [ "$WG_ROLE" = "server" ]; then
  PEER_PRIV="$(derive_key "client")"
else
  PEER_PRIV="$(derive_key "server")"
fi
PEER_PUB="$(printf '%s' "$PEER_PRIV" | wg pubkey)"
PSK="$(derive_psk)"

# Clear peer private key from memory (no longer needed)
unset PEER_PRIV

log "Local public key: $LOCAL_PUB"
log "Peer  public key: $PEER_PUB"

# --- Write config ---
mkdir -p /etc/wireguard
CFG="/etc/wireguard/${WG_IFACE}.conf"

cat > "$CFG" <<EOF
[Interface]
Address    = ${WG_ADDRESS}
ListenPort = ${WG_PORT}
PrivateKey = ${LOCAL_PRIV}

[Peer]
PublicKey    = ${PEER_PUB}
PresharedKey = ${PSK}
EOF

if [ "$WG_ROLE" = "server" ]; then
  SERVER_ALLOWED="${WG_ALLOWED_IPS:-${PEER_ADDRESS}/32}"
  echo "AllowedIPs = ${SERVER_ALLOWED}" >> "$CFG"
else
  echo "AllowedIPs           = ${WG_ALLOWED_IPS}" >> "$CFG"
  echo "Endpoint             = ${WG_SERVER_ENDPOINT}" >> "$CFG"
  echo "PersistentKeepalive  = ${WG_KEEPALIVE:-25}" >> "$CFG"
fi

# Restrict config file permissions (contains private key and PSK)
chmod 600 "$CFG"

# Clear sensitive variables
unset LOCAL_PRIV PSK WG_SECRET

# --- Cleanup on signal ---
cleanup() {
  log "Shutting down ${WG_IFACE}..."
  wg-quick down "$WG_IFACE" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

log "Starting WireGuard (${WG_ROLE}) on ${WG_ADDRESS} ..."
wg-quick up "$WG_IFACE"
log "WireGuard is running."

# Wait for signals (sleep infinity + wait allows immediate signal handling)
sleep infinity &
wait $!
