#!/bin/bash
# SessionStart hook: inject live project state as context
cd /Users/tal/wudan/dojo/iris

echo "=== Live Project State ==="
echo ""

# Recent commits
echo "Recent commits:"
git log --oneline -5 2>/dev/null
echo ""

# Uncommitted changes
CHANGES=$(git diff --stat 2>/dev/null)
if [[ -n "$CHANGES" ]]; then
    echo "Uncommitted changes:"
    echo "$CHANGES"
    echo ""
fi

# Staged changes
STAGED=$(git diff --cached --stat 2>/dev/null)
if [[ -n "$STAGED" ]]; then
    echo "Staged changes:"
    echo "$STAGED"
    echo ""
fi

# Files approaching 300-line limit
echo "Files approaching 300-line limit:"
find Packages IrisApp IrisEndpointExtension IrisNetworkExtension IrisProxyExtension IrisDNSExtension Shared -name "*.swift" -exec wc -l {} + 2>/dev/null | sort -rn | awk '$1 > 250 && !/total$/ {printf "  %d lines: %s\n", $1, $2}' | head -10
echo ""

# App running status
APP_PID=$(pgrep -x "Iris" 2>/dev/null)
if [[ -n "$APP_PID" ]]; then
    echo "Iris app: running (PID $APP_PID)"
else
    echo "Iris app: not running"
fi

# Extension process status
echo "Extension status:"
for ext in network endpoint proxy dns; do
    PID=$(pgrep -f "com.wudan.iris.${ext}.extension" 2>/dev/null)
    if [[ -n "$PID" ]]; then
        echo "  $ext: running (PID $PID)"
    else
        echo "  $ext: not running"
    fi
done

# Proxy tunnel status
TUNNEL=$(scutil --nc list 2>/dev/null | grep -i "iris" || true)
if [[ -n "$TUNNEL" ]]; then
    echo "Proxy tunnel: $TUNNEL"
else
    echo "Proxy tunnel: not configured"
fi

# CA certificate — check all keychains (data protection keychain not visible to login.keychain-db)
CA=$(security find-certificate -c "Iris" -a 2>/dev/null | grep "labl" | head -1 | sed 's/.*<blob>="//' | sed 's/"//' || true)
if [[ -n "$CA" ]]; then
    echo "CA certificate: $CA"
else
    # Fallback: check via app status
    if [[ -f /tmp/iris-status.json ]]; then
        CA_LOADED=$(python3 -c "import json; d=json.load(open('/tmp/iris-status.json')); print(d.get('ca',{}).get('loaded',False))" 2>/dev/null || true)
        if [[ "$CA_LOADED" == "True" ]]; then
            echo "CA certificate: loaded in app (data protection keychain)"
        else
            echo "CA certificate: not found"
        fi
    else
        echo "CA certificate: not found"
    fi
fi
echo ""

# Recent errors (no sudo — will only work if accessible)
ERRORS=$(log show --predicate 'subsystem BEGINSWITH "com.wudan.iris" AND messageType == 16' --last 5m --style compact 2>/dev/null | grep -v "^Timestamp" | tail -5)
if [[ -n "$ERRORS" ]]; then
    echo "Recent errors (last 5 min):"
    echo "$ERRORS"
fi

exit 0
