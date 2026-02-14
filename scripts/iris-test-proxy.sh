#!/bin/bash
# iris-test-proxy.sh — Test the MITM proxy pipeline end-to-end
# Generates HTTPS traffic and checks if the proxy captures it.
#
# Prerequisites:
#   - Iris app running with proxy extension active
#   - CA certificate trusted in System Keychain
#
# Usage: ./scripts/iris-test-proxy.sh

set -uo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

section() { echo -e "\n${CYAN}=== $1 ===${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail()    { echo -e "  ${RED}✗${NC} $1"; }

# 1. Check proxy extension is running
section "Proxy Extension"
PROXY_PID=$(pgrep -f "com.wudan.iris.proxy.extension" 2>/dev/null || true)
if [ -n "$PROXY_PID" ]; then
    ok "Proxy extension running (PID $PROXY_PID)"
else
    fail "Proxy extension not running — start it from Iris Settings"
    exit 1
fi

# 2. Check proxy tunnel status
section "Proxy Tunnel"
TUNNEL=$(scutil --nc list 2>/dev/null | grep -i "iris\|proxy" || echo "")
if [ -n "$TUNNEL" ]; then
    if echo "$TUNNEL" | grep -qi "Connected"; then
        ok "Tunnel connected"
    else
        warn "Tunnel exists but not connected:"
        echo "  $TUNNEL"
    fi
else
    warn "No proxy tunnel found in scutil"
fi

# 3. Send CLI status command
section "App Status (via CLI)"
if [ -f scripts/iris-ctl.swift ]; then
    swift scripts/iris-ctl.swift status 2>/dev/null
    if [ -f /tmp/iris-status.json ]; then
        ok "Status received"
        cat /tmp/iris-status.json
    else
        warn "No status response — is the app running?"
    fi
else
    warn "iris-ctl.swift not found"
fi

# 4. Generate test HTTPS traffic
section "Test Traffic Generation"
echo "  Making 3 HTTPS requests..."

# Request 1: Simple GET
STATUS1=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://httpbin.org/get 2>/dev/null || echo "000")
if [ "$STATUS1" = "200" ]; then
    ok "httpbin.org/get → $STATUS1"
else
    warn "httpbin.org/get → $STATUS1 (may be intercepted)"
fi

# Request 2: POST with body
STATUS2=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -X POST -d '{"test":"iris-proxy"}' -H "Content-Type: application/json" https://httpbin.org/post 2>/dev/null || echo "000")
if [ "$STATUS2" = "200" ]; then
    ok "httpbin.org/post → $STATUS2"
else
    warn "httpbin.org/post → $STATUS2"
fi

# Request 3: Different host
STATUS3=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://example.com 2>/dev/null || echo "000")
if [ "$STATUS3" = "200" ]; then
    ok "example.com → $STATUS3"
else
    warn "example.com → $STATUS3"
fi

# 5. Check recent proxy logs for flow capture
section "Recent Proxy Logs (last 30s)"
LOGS=$(sudo log show --predicate 'subsystem == "com.wudan.iris.proxy"' --last 30s --style compact 2>/dev/null | grep -v "^Timestamp" | tail -20 || echo "")
if [ -n "$LOGS" ]; then
    echo "$LOGS" | while read -r line; do
        echo "  $line"
    done
else
    warn "No proxy logs in last 30s"
fi

# 6. Check for TLS handshake activity
section "TLS Activity (last 30s)"
TLS_LOGS=$(sudo log show --predicate 'subsystem BEGINSWITH "com.wudan.iris" AND (message CONTAINS "TLS" OR message CONTAINS "certificate" OR message CONTAINS "handshake" OR message CONTAINS "MITM")' --last 30s --style compact 2>/dev/null | grep -v "^Timestamp" | tail -10 || echo "")
if [ -n "$TLS_LOGS" ]; then
    echo "$TLS_LOGS" | while read -r line; do
        echo "  $line"
    done
else
    warn "No TLS activity in last 30s"
fi

echo ""
echo "Done. If no flows were captured, check:"
echo "  1. Proxy tunnel is connected (scutil --nc list)"
echo "  2. CA certificate is trusted in System Settings > Certificates"
echo "  3. Proxy extension has received the CA (check logs with ./scripts/iris-logs.sh proxy)"
