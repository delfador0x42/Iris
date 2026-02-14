#!/bin/bash
# iris-logs.sh — Stream Iris extension logs in real-time
# Usage:
#   ./scripts/iris-logs.sh           # All Iris logs
#   ./scripts/iris-logs.sh proxy     # Proxy extension only
#   ./scripts/iris-logs.sh endpoint  # Endpoint extension only
#   ./scripts/iris-logs.sh tls       # TLS-related logs only
#   ./scripts/iris-logs.sh xpc       # XPC-related logs only
#   ./scripts/iris-logs.sh cli       # CLI command handler logs only
#   ./scripts/iris-logs.sh errors    # Errors only

FILTER="${1:-all}"

case "$FILTER" in
    proxy)
        PRED='subsystem == "com.wudan.iris.proxy"'
        ;;
    network)
        PRED='subsystem == "com.wudan.iris.network"'
        ;;
    endpoint)
        PRED='subsystem BEGINSWITH "com.wudan.iris.endpoint"'
        ;;
    dns)
        PRED='subsystem == "com.wudan.iris.dns"'
        ;;
    tls)
        PRED='subsystem BEGINSWITH "com.wudan.iris" AND (category == "TLS" OR category == "TLSInterceptor" OR message CONTAINS "TLS" OR message CONTAINS "certificate")'
        ;;
    xpc)
        PRED='subsystem BEGINSWITH "com.wudan.iris" AND (category == "XPC" OR message CONTAINS "XPC")'
        ;;
    cli)
        PRED='subsystem == "com.wudan.iris" AND category == "CLICommand"'
        ;;
    errors)
        PRED='subsystem BEGINSWITH "com.wudan.iris" AND messageType == 16'
        ;;
    all)
        PRED='subsystem BEGINSWITH "com.wudan.iris"'
        ;;
    *)
        echo "Usage: $0 [all|proxy|network|endpoint|dns|tls|xpc|cli|errors]"
        exit 1
        ;;
esac

echo "Streaming Iris logs (filter: $FILTER)..."
echo "Press Ctrl+C to stop"
echo "---"
log stream --predicate "$PRED" --style compact --level debug
