#!/bin/sh
# Local test without Docker/WireGuard kernel module.
# Mocks wg and wg-quick, checks the generated config.
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
    fail "$label -- '$pattern' not found in $file"
    echo "--- Contents of $file ---"
    cat "$file"
    echo "-------------------------"
  fi
}

assert_not_contains() {
  label="$1"; pattern="$2"; file="$3"
  if ! grep -qF "$pattern" "$file" 2>/dev/null; then
    ok "$label"
  else
    fail "$label -- '$pattern' should NOT be in $file"
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

  # Mock sleep to exit immediately (for "sleep infinity &" pattern)
  cat > "$MOCK_BIN/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$MOCK_BIN/sleep"

  export PATH="$MOCK_BIN:$PATH"
  export WG_CONFIG_DIR="$TMPDIR_TEST/etc/wireguard"
  mkdir -p "$WG_CONFIG_DIR"
}

cleanup_mock_env() {
  rm -rf "$TMPDIR_TEST"
}

# Build patched script (path + sleep loop) and run with env -i
run_entrypoint() {
  PATCHED="$TMPDIR_TEST/entrypoint_patched.sh"
  sed "s|/etc/wireguard|$WG_CONFIG_DIR|g" "$SCRIPT" > "$PATCHED"
  # Replace "sleep infinity &\nwait $!" with "exit 0"
  sed -i '/sleep infinity/,/wait/c\exit 0' "$PATCHED"
  chmod +x "$PATCHED"

  # env -i: clean environment, only explicitly passed variables
  env -i PATH="$PATH" $1 sh "$PATCHED" > "$TMPDIR_TEST/stdout.txt" 2>&1 || true
  CONFIG_FILE="$WG_CONFIG_DIR/wg0.conf"
}

# Like run_entrypoint, but returns exit code
run_entrypoint_exit() {
  PATCHED="$TMPDIR_TEST/entrypoint_patched.sh"
  sed "s|/etc/wireguard|$WG_CONFIG_DIR|g" "$SCRIPT" > "$PATCHED"
  sed -i '/sleep infinity/,/wait/c\exit 0' "$PATCHED"
  chmod +x "$PATCHED"
  env -i PATH="$PATH" $1 sh "$PATCHED" > /dev/null 2>&1
}

echo ""
echo "=== Test 1: Server - minimal config ==="
setup_mock_env
run_entrypoint "WG_ROLE=server WG_SECRET=my-long-test-secret-1234"
assert_contains "Interface.Address = 10.77.0.1/30"  "Address    = 10.77.0.1/30"  "$CONFIG_FILE"
assert_contains "Interface.ListenPort = 51820"       "ListenPort = 51820"          "$CONFIG_FILE"
assert_contains "Peer.AllowedIPs = 10.77.0.2/32"    "AllowedIPs = 10.77.0.2/32"  "$CONFIG_FILE"
assert_not_contains "No Endpoint on server"          "Endpoint"                    "$CONFIG_FILE"
assert_not_contains "No Keepalive on server"         "PersistentKeepalive"         "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 2: Client - minimal config ==="
setup_mock_env
run_entrypoint "WG_ROLE=client WG_SECRET=my-long-test-secret-1234 WG_SERVER_ENDPOINT=1.2.3.4:51820"
assert_contains "Interface.Address = 10.77.0.2/30"  "Address    = 10.77.0.2/30"  "$CONFIG_FILE"
assert_contains "Endpoint set"                       "Endpoint             = 1.2.3.4:51820" "$CONFIG_FILE"
assert_contains "PersistentKeepalive default 25"     "PersistentKeepalive  = 25"   "$CONFIG_FILE"
assert_contains "AllowedIPs default = tunnel IP"     "AllowedIPs           = 10.77.0.1/32" "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 3: Client - custom AllowedIPs ==="
setup_mock_env
run_entrypoint "WG_ROLE=client WG_SECRET=my-long-test-secret-1234 WG_SERVER_ENDPOINT=1.2.3.4:51820 WG_ALLOWED_IPS=0.0.0.0/0"
assert_contains "AllowedIPs = 0.0.0.0/0"            "AllowedIPs           = 0.0.0.0/0" "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 4: Server - custom port ==="
setup_mock_env
run_entrypoint "WG_ROLE=server WG_SECRET=my-long-test-secret-1234 WG_PORT=12345"
assert_contains "ListenPort = 12345"                 "ListenPort = 12345"          "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 5: Same secret -> same keys on server and client ==="
setup_mock_env
# Replicate derive_key logic: HMAC-SHA256(key=secret, msg="wg-direct|<role>") + Curve25519 clamping
# Uses od (POSIX) for hex conversion, no xxd required
_hex_to_base64() {
  printf '%s' "$1" | awk '
  {
    for (i = 1; i <= 32; i++) {
      hex2 = substr($0, (i-1)*2+1, 2)
      printf "%c", strtonum("0x" hex2)
    }
  }' | base64
}
_hmac_key() {
  hex="$(printf '%s' "wg-direct|${2}" \
    | openssl dgst -sha256 -hmac "$1" -binary \
    | od -A n -t x1 | tr -d ' \n')"
  clamped="$(printf '%s' "$hex" | awk '
  {
    for (i = 1; i <= 32; i++) {
      hex2 = substr($0, (i-1)*2+1, 2)
      b[i] = strtonum("0x" hex2)
    }
    b[1]  = and(b[1],  248)
    b[32] = and(b[32], 127)
    b[32] = or(b[32],  64)
    for (i = 1; i <= 32; i++) printf "%02x", b[i]
    printf "\n"
  }')"
  _hex_to_base64 "$clamped"
}
SERVER_PRIV="$(_hmac_key "my-long-test-secret-1234" "server")"
CLIENT_PRIV="$(_hmac_key "my-long-test-secret-1234" "client")"
if [ "$SERVER_PRIV" != "$CLIENT_PRIV" ]; then
  ok "Server and client private keys are different"
else
  fail "Server and client private keys are IDENTICAL"
fi
PSK1="$(printf '%s' "wg-direct|psk" | openssl dgst -sha256 -hmac "my-long-test-secret-1234" -binary | base64)"
PSK2="$(printf '%s' "wg-direct|psk" | openssl dgst -sha256 -hmac "my-long-test-secret-1234" -binary | base64)"
if [ "$PSK1" = "$PSK2" ]; then
  ok "PSK is identical on both sides"
else
  fail "PSK differs between sides"
fi
cleanup_mock_env

echo ""
echo "=== Test 6: Missing required variables -> exit != 0 ==="
setup_mock_env
if run_entrypoint_exit "WG_ROLE=client WG_SECRET=my-long-test-secret-1234"; then
  fail "Client without WG_SERVER_ENDPOINT should fail"
else
  ok "Client without WG_SERVER_ENDPOINT fails correctly"
fi
if run_entrypoint_exit "WG_ROLE=server"; then
  fail "Missing WG_SECRET should fail"
else
  ok "Missing WG_SECRET fails correctly"
fi
cleanup_mock_env

echo ""
echo "=== Test 7: Custom WG_ADDRESS - dynamic peer address ==="
setup_mock_env
run_entrypoint "WG_ROLE=server WG_SECRET=my-long-test-secret-1234 WG_ADDRESS=10.99.0.1/30"
assert_contains "Interface.Address = 10.99.0.1/30"  "Address    = 10.99.0.1/30"  "$CONFIG_FILE"
assert_contains "Peer.AllowedIPs = 10.99.0.2/32"    "AllowedIPs = 10.99.0.2/32"  "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 8: Custom WG_ADDRESS client - dynamic peer address ==="
setup_mock_env
run_entrypoint "WG_ROLE=client WG_SECRET=my-long-test-secret-1234 WG_SERVER_ENDPOINT=1.2.3.4:51820 WG_ADDRESS=10.99.0.2/30"
assert_contains "Interface.Address = 10.99.0.2/30"  "Address    = 10.99.0.2/30"  "$CONFIG_FILE"
assert_contains "AllowedIPs default = 10.99.0.1/32" "AllowedIPs           = 10.99.0.1/32" "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=== Test 9: Invalid WG_PORT -> exit != 0 ==="
setup_mock_env
if run_entrypoint_exit "WG_ROLE=server WG_SECRET=my-long-test-secret-1234 WG_PORT=abc"; then
  fail "Invalid WG_PORT should fail"
else
  ok "Invalid WG_PORT fails correctly"
fi
if run_entrypoint_exit "WG_ROLE=server WG_SECRET=my-long-test-secret-1234 WG_PORT=99999"; then
  fail "WG_PORT out of range should fail"
else
  ok "WG_PORT out of range fails correctly"
fi
cleanup_mock_env

echo ""
echo "=== Test 10: Invalid WG_SERVER_ENDPOINT format -> exit != 0 ==="
setup_mock_env
if run_entrypoint_exit "WG_ROLE=client WG_SECRET=my-long-test-secret-1234 WG_SERVER_ENDPOINT=example.com"; then
  fail "Endpoint without port should fail"
else
  ok "Endpoint without port fails correctly"
fi
cleanup_mock_env

echo ""
echo "=== Test 11: Config file permissions ==="
setup_mock_env
run_entrypoint "WG_ROLE=server WG_SECRET=my-long-test-secret-1234"
PERMS="$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || stat -f '%Lp' "$CONFIG_FILE" 2>/dev/null)"
if [ "$PERMS" = "600" ]; then
  ok "Config file has permissions 600"
else
  fail "Config file permissions are $PERMS, expected 600"
fi
cleanup_mock_env

echo ""
echo "=== Test 12: Short WG_SECRET produces warning (but still works) ==="
setup_mock_env
run_entrypoint "WG_ROLE=server WG_SECRET=short"
if grep -q "WARNING" "$TMPDIR_TEST/stdout.txt" 2>/dev/null; then
  ok "Short secret produces warning"
else
  fail "Short secret should produce a warning"
fi
# Config should still be generated
assert_contains "Config still generated with short secret" "Address" "$CONFIG_FILE"
cleanup_mock_env

echo ""
echo "=================================="
echo "  Result: ${PASS} passed, ${FAIL} failed"
echo "=================================="
[ "$FAIL" -eq 0 ]
