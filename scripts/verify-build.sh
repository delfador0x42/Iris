#!/bin/bash
# Stop hook: build must pass before Claude can stop
INPUT=$(cat)
STOP_HOOK_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')

# Prevent infinite loop — if we're already in a stop hook retry, let it through
if [[ "$STOP_HOOK_ACTIVE" == "true" ]]; then
    exit 0
fi

cd /Users/tal/wudan/dojo/iris

# Quick build check — errors only
BUILD_OUTPUT=$(xcodebuild -project Iris.xcodeproj -scheme Iris -configuration Debug build 2>&1)
BUILD_EXIT=$?

if [[ $BUILD_EXIT -ne 0 ]]; then
    # Extract just the errors, not the full build log
    ERRORS=$(echo "$BUILD_OUTPUT" | grep -E "error:" | head -10)
    echo "Build failed. Fix these errors:" >&2
    echo "$ERRORS" >&2
    exit 2  # Block — force Claude to continue and fix
fi

exit 0
