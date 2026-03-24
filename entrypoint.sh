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

# Convert hex string to binary and output as base64.
# Uses printf \xNN escapes (POSIX) — avoids gawk-only strtonum().
hex_to_base64() {
  _hex="$1"
  _n=$(( ${#_hex} / 2 ))
  _i=0
  _out=""
  while [ $_i -lt $_n ]; do
    _byte=$(printf '%s' "$_hex" | cut -c$(( _i*2+1 ))-$(( _i*2+2 )))
    _out="${_out}$(printf "\\x${_byte}")"
    _i=$(( _i + 1 ))
  done
  printf '%s' "$_out" | base64 | tr -d '\n'
  echo
}

# Derive deterministic Curve25519 private key from secret + role.
# Uses HMAC-SHA256(key=secret, msg="wg-direct|<role>") as KDF.
# The 32-byte output is clamped to a valid Curve25519 scalar.
# Requires: openssl, od, cut, base64 — no gawk needed.
derive_key() {
  role="$1"
  # HMAC-SHA256: key=WG_SECRET, message="wg-direct|<role>"
  hex="$(printf '%s' "wg-direct|${role}" \
    | openssl dgst -sha256 -hmac "$WG_SECRET" -binary \
    | od -A n -t x1 | tr -d ' \n')"

  # Curve25519 scalar clamping via POSIX shell arithmetic:
  # byte[0]  &= 0xF8  (clear lowest 3 bits)
  # byte[31] &= 0x7F  (clear highest bit)
  # byte[31] |= 0x40  (set second-highest bit)
  _b1=$(( $(printf '%d' "0x$(printf '%s' "$hex" | cut -c1-2)") & 248 ))
  _b32=$(( $(printf '%d' "0x$(printf '%s' "$hex" | cut -c63-64)") & 127 | 64 ))

  clamped=""
  _i=0
  while [ $_i -lt 32 ]; do
    _byte_hex=$(printf '%s' "$hex" | cut -c$(( _i*2+1 ))-$(( _i*2+2 )))
    if [ $_i -eq 0 ]; then
      clamped="${clamped}$(printf '%02x' $_b1)"
    elif [ $_i -eq 31 ]; then
      clamped="${clamped}$(printf '%02x' $_b32)"
    else
      clamped="${clamped}${_byte_hex}"
    fi
    _i=$(( _i + 1 ))
  done

  hex_to_base64 "$clamped"
}

# Derive preshared key from secret (symmetric, role-independent).
# Uses HMAC-SHA256(key=secret, msg="wg-direct|psk").
derive_psk() {
  printf '%s' "wg-direct|psk" \
    | openssl dgst -sha256 -hmac "$WG_SECRET" -binary \
    | base64
}

# Calculate peer address from own WG_ADDRESS (CIDR notation).
# For /30 or /31: toggle between the two usable host IPs.
# For larger subnets: server=.1, client=.2
calc_peer_address() {
  my_cidr="$1"
  role="$2"

  # Split IP and prefix
  my_ip="${my_cidr%/*}"
  prefix="${my_cidr#*/}"

  # Convert IP to integer
  ip_to_int() {
    echo "$1" | awk -F. '{ print ($1*16777216) + ($2*65536) + ($3*256) + $4 }'
  }

  # Convert integer to dotted IP
  int_to_ip() {
    awk -v n="$1" 'BEGIN {
      printf "%d.%d.%d.%d\n",
        int(n/16777216)%256,
        int(n/65536)%256,
        int(n/256)%256,
        n%256
    }'
  }

  my_int="$(ip_to_int "$my_ip")"
  mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
  net_int=$(( my_int & mask ))

  if [ "$prefix" -ge 30 ]; then
    # /30 or /31: toggle between the two host IPs
    host1=$(( net_int + 1 ))
    host2=$(( net_int + 2 ))
    if [ "$my_int" -eq "$host1" ]; then
      int_to_ip "$host2"
    elif [ "$my_int" -eq "$host2" ]; then
      int_to_ip "$host1"
    else
      die "calc_peer_address: $my_ip is not a valid host in ${my_cidr}"
    fi
  else
    # Larger subnets: server=.1, client=.2
    if [ "$role" = "server" ]; then
      int_to_ip $(( net_int + 2 ))  # peer is client = .2
    else
      int_to_ip $(( net_int + 1 ))  # peer is server = .1
    fi
  fi
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
