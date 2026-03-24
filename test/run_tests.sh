#!/bin/sh
# Lokaler Test ohne Docker/WireGuard-Kernel-Modul.
# Mockt wg und wg-quick, prueft die generierte Config.
set -eu

PASS=0
FAIL=0
SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/entrypoint.sh"

ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

assert_contains() {
  label="$1"; pattern="$2"; file="$3"
  if grep -qF "$pattern" "$file" 2>/dev/null; then
    ok "$label"
  else
    fail "$label -- '$pattern' nicht in $file gefunden"
    echo "--- Inhalt von $file ---"
    cat "$file"
    echo "------------------------"
  fi
}

assert_not_contains() {
  label="$1"; pattern="$2"; file="$3"
  if ! grep -qF "$pattern" "$file" 2>/dev/null; then
    ok "$label"
  else
    fail "$label -- '$pattern' sollte NICHT in $file stehen"
  fi
}

setup_mock_env() {
  TMPDIR_TEST="$(mktemp -d)"
  MOCK_BIN="$TMPDIR_TEST/bin"
  mkdir -p "$MOCK_BIN"

  cat > "$MOCK_BIN/wg" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "pubkey" ]; then
  input="$(cat)"
  echo "PUBKEY_$(echo "$input" | head -c 8 | od -A n -t x1 | tr -d ' \n')"
fi
EOF
  chmod +x "$MOCK_BIN/wg"

  cat > "$MOCK_BIN/wg-quick" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$MOCK_BIN/wg-quick"

  cat > "$MOCK_BIN/sysctl" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$MOCK_BIN/sysctl"

  cat > "$MOCK_BIN/iptables" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$MOCK_BIN/iptables"

  export PATH="$MOCK_BIN:$PATH"
  export WG_CONFIG_DIR="$TMPDIR_TEST/etc/wireguard"
  mkdir -p "$WG_CONFIG_DIR"
}

cleanup_mock_env() {
  rm -rf "$TMPDIR_TEST"
}

# Baut gepatchtes Skript (Pfad + sleep-Loop) und fuehrt es mit env -i aus
run_entrypoint() {
  PATCHED="$TMPDIR_TEST/entrypoint_patched.sh"
  sed "s|/etc/wireguard|$WG_CONFIG_DIR|g" "$SCRIPT" > "$PATCHED"
  sed -i 's/while true; do sleep 3600; done/exit 0/' "$PATCHED"
  chmod +x "$PATCHED"

  # env -i: saubere Umgebung, nur explizit uebergebene Variablen
  env -i PATH="$PATH" $1 sh "$PATCHED" > "$TMPDIR_TEST/stdout.txt" 2>&1 || true
  CONFIG_FILE="$WG_CONFIG_DIR/wg0.conf"
}

# Wie run_entrypoint, aber gibt Exit-Code zurueck
run_entrypoint_exit() {
  PATCHED="$TMPDIR_TEST/entrypoint_patched.sh"
  sed "s|/etc/wireguard|$WG_CONFIG_DIR|g" "$SCRIPT" > "$PATCHED"
  sed -i 's/while true; do sleep 3600; done/exit 0/' "$PATCHED"
  chmod +x "$PATCHED"
  env -i PATH="$PATH" $1 sh "$PATCHED" > /dev/null 2>&1
}

echo ""
echo "=== Test 1: Server - minimale Config ==="
setup_mock_env
run_entrypoint "WG_ROLE=server WG_SECRET=mein-geheimnis"
assert_contains "Interface.Address = 10.77.0.1/30"  "Address    = 10.77.0.1/30"  "$CONFIG_FILE"
assert_contains "Interface.ListenPort = 51820"       "ListenPort = 51820"          "$CONFIG_FILE"
assert_contains "Peer.AllowedIPs = 10.77.0.2/32"    "AllowedIPs = 10.77.0.2/32"  "$CONFIG_FILE"
assert_not_contains "Kein Endpoint beim Server"      "Endpoint"                    "$CONFIG_FILE"
assert_not_contains "Kein Keepalive beim Server"     "PersistentKeepalive"         "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 2: Client - minimale Config ==="
setup_mock_env
run_entrypoint "WG_ROLE=client WG_SECRET=mein-geheimnis WG_SERVER_ENDPOINT=1.2.3.4:51820"
assert_contains "Interface.Address = 10.77.0.2/30"  "Address    = 10.77.0.2/30"  "$CONFIG_FILE"
assert_contains "Endpoint gesetzt"                   "Endpoint             = 1.2.3.4:51820" "$CONFIG_FILE"
assert_contains "PersistentKeepalive Default 25"     "PersistentKeepalive  = 25"   "$CONFIG_FILE"
assert_contains "AllowedIPs Default = Tunnel-IP"     "AllowedIPs           = 10.77.0.1/32" "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 3: Client - eigene AllowedIPs ==="
setup_mock_env
run_entrypoint "WG_ROLE=client WG_SECRET=mein-geheimnis WG_SERVER_ENDPOINT=1.2.3.4:51820 WG_ALLOWED_IPS=0.0.0.0/0"
assert_contains "AllowedIPs = 0.0.0.0/0"            "AllowedIPs           = 0.0.0.0/0" "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 4: Server - eigener Port ==="
setup_mock_env
run_entrypoint "WG_ROLE=server WG_SECRET=mein-geheimnis WG_PORT=12345"
assert_contains "ListenPort = 12345"                 "ListenPort = 12345"          "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 5: Gleicher Secret -> gleiche Keys auf Server und Client ==="
setup_mock_env
SERVER_PRIV="$(WG_SECRET=mein-geheimnis python3 -c "
import base64,hashlib,os
secret=os.environ['WG_SECRET']
seed=hashlib.sha256(f'{secret}|server'.encode()).digest()
b=bytearray(seed); b[0]&=248; b[31]&=127; b[31]|=64
print(base64.b64encode(bytes(b)).decode())
")"
CLIENT_PRIV="$(WG_SECRET=mein-geheimnis python3 -c "
import base64,hashlib,os
secret=os.environ['WG_SECRET']
seed=hashlib.sha256(f'{secret}|client'.encode()).digest()
b=bytearray(seed); b[0]&=248; b[31]&=127; b[31]|=64
print(base64.b64encode(bytes(b)).decode())
")"
if [ "$SERVER_PRIV" != "$CLIENT_PRIV" ]; then
  ok "Server- und Client-PrivKey sind verschieden"
else
  fail "Server- und Client-PrivKey sind GLEICH"
fi
PSK1="$(WG_SECRET=mein-geheimnis python3 -c "
import base64,hashlib,os
seed=hashlib.sha256(f\"{os.environ['WG_SECRET']}|psk\".encode()).digest()
print(base64.b64encode(seed).decode())
")"
PSK2="$(WG_SECRET=mein-geheimnis python3 -c "
import base64,hashlib,os
seed=hashlib.sha256(f\"{os.environ['WG_SECRET']}|psk\".encode()).digest()
print(base64.b64encode(seed).decode())
")"
if [ "$PSK1" = "$PSK2" ]; then
  ok "PSK ist auf beiden Seiten identisch"
else
  fail "PSK weicht ab"
fi
cleanup_mock_env

echo ""
echo "=== Test 6: Fehlende Pflicht-Variablen -> Exit != 0 ==="
setup_mock_env
if run_entrypoint_exit "WG_ROLE=client WG_SECRET=x"; then
  fail "Client ohne WG_SERVER_ENDPOINT sollte fehlschlagen"
else
  ok "Client ohne WG_SERVER_ENDPOINT schlaegt korrekt fehl"
fi
if run_entrypoint_exit "WG_ROLE=server"; then
  fail "Fehlender WG_SECRET sollte fehlschlagen"
else
  ok "Fehlender WG_SECRET schlaegt korrekt fehl"
fi
cleanup_mock_env

echo ""
echo "=================================="
echo "  Ergebnis: ${PASS} bestanden, ${FAIL} fehlgeschlagen"
echo "=================================="
[ "$FAIL" -eq 0 ]
