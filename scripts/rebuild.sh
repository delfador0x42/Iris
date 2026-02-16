#!/bin/bash
set -euo pipefail

TEAM_ID="99HGW2AR62"
BUNDLE_PREFIX="com.wudan.iris"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SYSEXT_DIR="/Library/SystemExtensions"
SYSEXT_DB="$SYSEXT_DIR/db.plist"
APP_DST="/Applications/Iris.app"

echo "=== Iris full rebuild ==="

# 1. Kill Iris + extensions
echo "[kill] stopping processes..."
killall Iris 2>/dev/null && echo "  Iris stopped" || true
for ext in network endpoint proxy dns; do
  killall "com.wudan.iris.${ext}.extension" 2>/dev/null && echo "  ${ext} stopped" || true
done
sleep 1

# 2. Remove system extensions from filesystem (ground truth)
echo "[sysext] removing from $SYSEXT_DIR..."
if [ -f "$SYSEXT_DB" ]; then
  # Find UUIDs for our extensions from db.plist
  UUIDS=$(sudo plutil -p "$SYSEXT_DB" 2>/dev/null \
    | grep -B5 "$BUNDLE_PREFIX" \
    | grep "uniqueID" \
    | sed 's/.*"\(.*\)"/\1/' || true)

  for uuid in $UUIDS; do
    if [ -d "$SYSEXT_DIR/$uuid" ]; then
      sudo rm -rf "$SYSEXT_DIR/$uuid"
      echo "  removed $uuid"
    fi
  done

  # Rebuild db.plist without our extensions
  # Export to xml, filter, convert back
  TMPDB=$(mktemp /tmp/sysext_db.XXXXXX.plist)
  sudo plutil -convert xml1 -o "$TMPDB" "$SYSEXT_DB" 2>/dev/null

  # Use python to remove our entries from the extensions array
  sudo python3 -c "
import plistlib, sys
with open('$TMPDB', 'rb') as f:
    db = plistlib.load(f)
exts = db.get('extensions', [])
kept = [e for e in exts if not e.get('identifier','').startswith('$BUNDLE_PREFIX')]
removed = len(exts) - len(kept)
db['extensions'] = kept
with open('$TMPDB', 'wb') as f:
    plistlib.dump(db, f)
print(f'  purged {removed} entries from db.plist')
"
  sudo cp "$TMPDB" "$SYSEXT_DB"
  rm -f "$TMPDB"
else
  echo "  no db.plist found"
fi

# 3. Remove from /Applications
if [ -d "$APP_DST" ]; then
  rm -rf "$APP_DST"
  echo "[app] removed $APP_DST"
fi

# 4. Nuke ALL Iris DerivedData (prevents cross-wiring)
echo "[clean] removing stale DerivedData..."
for dd in ~/Library/Developer/Xcode/DerivedData/Iris-*/; do
  if [ -d "$dd" ]; then
    rm -rf "$dd"
    echo "  removed $(basename "$dd")"
  fi
done

# 5. Build
echo "[build] building..."
cd "$PROJECT_DIR"
xcodebuild \
  -scheme Iris \
  -configuration Debug \
  build \
  2>&1 | tail -5

# Find the new DerivedData
DD_NEW=$(ls -dt ~/Library/Developer/Xcode/DerivedData/Iris-*/ 2>/dev/null | head -1)
APP_SRC="${DD_NEW}Build/Products/Debug/Iris.app"

if [ ! -d "$APP_SRC" ]; then
  echo "[build] FAILED — Iris.app not found at $APP_SRC"
  exit 1
fi
echo "[build] succeeded"

# 6. Copy to /Applications
cp -R "$APP_SRC" "$APP_DST"
echo "[install] copied to $APP_DST"

# 7. Verify
echo ""
echo "=== Verify ==="
echo "Extensions bundled:"
ls "$APP_DST/Contents/Library/SystemExtensions/" 2>/dev/null | sed 's/^/  /'
echo ""
echo "Launch Iris to activate system extensions."
