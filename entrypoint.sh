#!/bin/sh
set -eu

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

die() {
  echo "FEHLER: $*" >&2
  exit 1
}

# Deterministischen Curve25519-Private-Key aus Secret + Rolle ableiten
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

# Preshared Key aus Secret ableiten (symmetrisch, rollenunabhängig)
derive_psk() {
  python3 - "$WG_SECRET" <<'PY'
import base64, hashlib, sys
seed = hashlib.sha256(f"{sys.argv[1]}|psk".encode()).digest()
print(base64.b64encode(seed).decode())
PY
}

# --- Pflicht-Variablen ---
WG_ROLE="${WG_ROLE:-}"
WG_SECRET="${WG_SECRET:-}"

[ -z "$WG_ROLE" ]   && die "WG_ROLE muss 'server' oder 'client' sein."
[ -z "$WG_SECRET" ] && die "WG_SECRET ist nicht gesetzt."

case "$WG_ROLE" in
  server|client) ;;
  *) die "WG_ROLE muss 'server' oder 'client' sein." ;;
esac

# --- Optionale Variablen mit Defaults ---
WG_PORT="${WG_PORT:-51820}"
WG_IFACE="${WG_IFACE:-wg0}"

# Tunnel-IPs: Server = .1, Client = .2
if [ "$WG_ROLE" = "server" ]; then
  WG_ADDRESS="${WG_ADDRESS:-10.77.0.1/30}"
  PEER_ADDRESS="10.77.0.2"
else
  WG_ADDRESS="${WG_ADDRESS:-10.77.0.2/30}"
  PEER_ADDRESS="10.77.0.1"
  WG_SERVER_ENDPOINT="${WG_SERVER_ENDPOINT:-}"
  [ -z "$WG_SERVER_ENDPOINT" ] && die "WG_SERVER_ENDPOINT muss beim Client gesetzt sein (z.B. 1.2.3.4:51820)."
  # Default AllowedIPs beim Client: nur Tunnel-Gegenstelle
  WG_ALLOWED_IPS="${WG_ALLOWED_IPS:-${PEER_ADDRESS}/32}"
fi

# --- Keys ableiten ---
log "Leite Schlüssel aus Secret ab..."
LOCAL_PRIV="$(derive_key "$WG_ROLE")"
LOCAL_PUB="$(printf '%s' "$LOCAL_PRIV" | wg pubkey)"

if [ "$WG_ROLE" = "server" ]; then
  PEER_PRIV="$(derive_key "client")"
else
  PEER_PRIV="$(derive_key "server")"
fi
PEER_PUB="$(printf '%s' "$PEER_PRIV" | wg pubkey)"
PSK="$(derive_psk)"

log "Lokaler Public Key : $LOCAL_PUB"
log "Peer   Public Key  : $PEER_PUB"

# --- Config schreiben ---
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
  # Server: AllowedIPs = nur Tunnel-IP des Clients (kein Default-Route-Hijack)
  SERVER_ALLOWED="${WG_ALLOWED_IPS:-${PEER_ADDRESS}/32}"
  echo "AllowedIPs = ${SERVER_ALLOWED}" >> "$CFG"
else
  echo "AllowedIPs           = ${WG_ALLOWED_IPS}" >> "$CFG"
  echo "Endpoint             = ${WG_SERVER_ENDPOINT}" >> "$CFG"
  echo "PersistentKeepalive  = ${WG_KEEPALIVE:-25}" >> "$CFG"
fi

# --- Cleanup bei Signal ---
cleanup() {
  log "Fahre ${WG_IFACE} herunter..."
  wg-quick down "$WG_IFACE" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

log "Starte WireGuard (${WG_ROLE}) auf ${WG_ADDRESS} ..."
wg-quick up "$WG_IFACE"
log "WireGuard läuft."

while true; do sleep 3600; done
