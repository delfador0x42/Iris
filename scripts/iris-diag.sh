#!/bin/bash
# iris-diag.sh — Quick diagnostic snapshot of all Iris components
# Run: ./scripts/iris-diag.sh

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

# 1. System Extensions
section "System Extensions"
EXT_LIST=$(systemextensionsctl list 2>&1 || true)
for ext in network endpoint proxy dns; do
    BUNDLE="com.wudan.iris.${ext}.extension"
    if echo "$EXT_LIST" | grep -q "$BUNDLE.*activated enabled"; then
        ok "$ext extension: activated + enabled"
    elif echo "$EXT_LIST" | grep -q "$BUNDLE"; then
        STATUS=$(echo "$EXT_LIST" | grep "$BUNDLE" | awk '{print $NF}')
        warn "$ext extension: $STATUS"
    else
        fail "$ext extension: not installed"
    fi
done

# 2. Extension Processes
section "Extension Processes"
for ext in network endpoint proxy dns; do
    PID=$(pgrep -f "com.wudan.iris.${ext}.extension" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        USER=$(ps -o user= -p "$PID" 2>/dev/null || echo "?")
        ok "$ext extension: PID $PID (user: $USER)"
    else
        fail "$ext extension: not running"
    fi
done

# 3. Proxy Status (NETransparentProxyManager)
section "Transparent Proxy"
PROXY_STATUS=$(scutil --nc list 2>/dev/null | grep -i "iris\|proxy" || echo "none")
if [ "$PROXY_STATUS" != "none" ]; then
    if echo "$PROXY_STATUS" | grep -qi "Connected"; then
        ok "Proxy tunnel: Connected"
    elif echo "$PROXY_STATUS" | grep -qi "Disconnected"; then
        warn "Proxy tunnel: Disconnected"
    else
        echo "  $PROXY_STATUS"
    fi
else
    warn "Proxy tunnel: not in scutil list"
fi

# 4. CA Certificate
section "CA Certificate"
CERT=$(security find-certificate -c "Iris" login.keychain-db 2>/dev/null || true)
if [ -n "$CERT" ]; then
    LABEL=$(echo "$CERT" | grep "labl" | head -1 | sed 's/.*<blob>="//' | sed 's/"//')
    ok "CA certificate found: $LABEL"
else
    warn "No Iris CA certificate in login keychain"
fi

# 5. Zombie Extensions
section "Zombie Extensions"
ZOMBIES=$(echo "$EXT_LIST" | grep -c "waiting to uninstall" 2>/dev/null || echo "0")
if [ "$ZOMBIES" -gt 0 ]; then
    warn "$ZOMBIES zombie extension(s) waiting to uninstall"
    echo "$EXT_LIST" | grep "waiting to uninstall" | while read -r line; do
        echo "    $line"
    done
else
    ok "No zombie extensions"
fi

# 6. Recent Errors (last 60s)
section "Recent Errors (last 60s)"
ERRORS=$(sudo log show --predicate 'subsystem BEGINSWITH "com.wudan.iris" AND messageType == 16' --last 60s --style compact 2>/dev/null | grep -v "^Timestamp" | head -10)
if [ -n "$ERRORS" ]; then
    warn "Found errors:"
    echo "$ERRORS" | while read -r line; do
        echo "    $line"
    done
else
    ok "No errors in last 60s"
fi

# 7. Temp Keychain Cleanup
section "Temp Keychains"
TEMPS=$(ls /tmp/iris-id-*.keychain 2>/dev/null | wc -l | tr -d ' ')
if [ "$TEMPS" -gt 0 ]; then
    warn "$TEMPS leftover temp keychain(s) in /tmp"
else
    ok "No leftover temp keychains"
fi

# 8. Codebase Stats
section "Codebase Stats"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SWIFT_FILES=$(find "$PROJECT_DIR"/Packages "$PROJECT_DIR"/IrisApp "$PROJECT_DIR"/IrisEndpointExtension "$PROJECT_DIR"/IrisNetworkExtension "$PROJECT_DIR"/IrisProxyExtension "$PROJECT_DIR"/IrisDNSExtension "$PROJECT_DIR"/Shared -name "*.swift" 2>/dev/null | wc -l | tr -d ' ')
ok "$SWIFT_FILES Swift source files"
OVER_300=$(find "$PROJECT_DIR"/Packages "$PROJECT_DIR"/IrisApp "$PROJECT_DIR"/IrisEndpointExtension "$PROJECT_DIR"/IrisNetworkExtension "$PROJECT_DIR"/IrisProxyExtension "$PROJECT_DIR"/IrisDNSExtension "$PROJECT_DIR"/Shared -name "*.swift" -exec wc -l {} + 2>/dev/null | awk '$1 > 300 && !/total$/' | wc -l | tr -d ' ')
if [ "$OVER_300" -gt 0 ]; then
    warn "$OVER_300 file(s) over 300 lines"
    find "$PROJECT_DIR"/Packages "$PROJECT_DIR"/IrisApp "$PROJECT_DIR"/IrisEndpointExtension "$PROJECT_DIR"/IrisNetworkExtension "$PROJECT_DIR"/IrisProxyExtension "$PROJECT_DIR"/IrisDNSExtension "$PROJECT_DIR"/Shared -name "*.swift" -exec wc -l {} + 2>/dev/null | sort -rn | awk '$1 > 300 && !/total$/ {printf "    %d lines: %s\n", $1, $2}' | head -5
else
    ok "No files over 300 lines"
fi
TOP5=$(find "$PROJECT_DIR"/Packages "$PROJECT_DIR"/IrisApp "$PROJECT_DIR"/IrisEndpointExtension "$PROJECT_DIR"/IrisNetworkExtension "$PROJECT_DIR"/IrisProxyExtension "$PROJECT_DIR"/IrisDNSExtension "$PROJECT_DIR"/Shared -name "*.swift" -exec wc -l {} + 2>/dev/null | sort -rn | awk '!/total$/' | head -5)
echo "  Top 5 largest:"
echo "$TOP5" | while read -r line; do echo "    $line"; done

# 9. JSON Output (for machine parsing)
if [ "${1:-}" = "--json" ]; then
    echo ""
    section "JSON Report"
    # Collect statuses
    JSON_EXTS="{"
    for ext in network endpoint proxy dns; do
        BUNDLE="com.wudan.iris.${ext}.extension"
        PID=$(pgrep -f "$BUNDLE" 2>/dev/null || true)
        if echo "$EXT_LIST" | grep -q "$BUNDLE.*activated enabled" && [ -n "$PID" ]; then
            STATUS="healthy"
        elif [ -n "$PID" ]; then
            STATUS="degraded"
        else
            STATUS="down"
        fi
        JSON_EXTS="$JSON_EXTS\"$ext\":\"$STATUS\","
    done
    JSON_EXTS="${JSON_EXTS%,}}"

    CA_OK="false"
    [ -n "$CERT" ] && CA_OK="true"

    jq -n \
        --argjson extensions "$JSON_EXTS" \
        --argjson ca_present "$CA_OK" \
        --argjson zombie_count "$ZOMBIES" \
        --argjson temp_keychains "$TEMPS" \
        --argjson swift_files "$SWIFT_FILES" \
        --argjson files_over_300 "$OVER_300" \
        '{
            timestamp: now | todate,
            extensions: $extensions,
            ca_certificate: $ca_present,
            zombie_extensions: $zombie_count,
            temp_keychains: $temp_keychains,
            codebase: {
                swift_files: $swift_files,
                files_over_300: $files_over_300
            }
        }'
fi

echo ""
