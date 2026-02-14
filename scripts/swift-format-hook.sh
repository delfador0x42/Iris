#!/bin/bash
# PostToolUse hook: auto-format Swift files after Edit/Write
INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

# Only format Swift files
if [[ "$FILE_PATH" == *.swift ]] && [[ -f "$FILE_PATH" ]]; then
    xcrun swift-format -i "$FILE_PATH" 2>/dev/null

    # File size guard: warn if approaching 300-line limit
    LINES=$(wc -l < "$FILE_PATH" | tr -d ' ')
    if [[ "$LINES" -gt 280 ]]; then
        echo "WARNING: $FILE_PATH is $LINES lines (limit: 300). Consider splitting." >&2
    fi
fi

exit 0
