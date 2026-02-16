#!/bin/bash
set -e

TEAM_ID="99HGW2AR62"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DERIVED="$HOME/Library/Developer/Xcode/DerivedData/Iris-fznqfxaigrzhtagttswrnzlzrdhg"
BUILD_DIR="$DERIVED/Build/Products/Debug"
APP_SRC="$BUILD_DIR/Iris.app"

echo "=== Iris rebuild & reinstall ==="

# 1. Kill Iris if running
killall Iris 2>/dev/null && echo "[kill] Iris stopped" || echo "[kill] not running"
sleep 1

# 2. Uninstall all system extensions
echo "[sysext] uninstalling..."
for ext in network endpoint proxy dns; do
  BUNDLE="com.wudan.iris.${ext}.extension"
  sudo systemextensionsctl uninstall "$TEAM_ID" "$BUNDLE" 2>/dev/null \
    && echo "  $ext removed" || echo "  $ext not installed"
done

# 3. Remove from /Applications
rm -rf /Applications/Iris.app && echo "[app] removed from /Applications"

# 4. Clean DerivedData
rm -rf "$BUILD_DIR" && echo "[clean] build dir removed"

# 5. Build
#echo "[build] building..."
#cd "$PROJECT_DIR"
#xcodebuild build \
#  -scheme Iris \
#  -configuration Debug \
#  -destination 'platform=macOS' \
#  -derivedDataPath "$DERIVED" \
#  2>&1 | tail -5
#
#if [ ! -d "$APP_SRC" ]; then
#  echo "[build] FAILED — Iris.app not found"
#  exit 1
#fi
#echo "[build] succeeded"
#
## 6. Copy to /Applications
#cp -R "$APP_SRC" /Applications/Iris.app
#echo "[install] copied to /Applications/Iris.app"
#
#echo "=== Done. Launch Iris to activate system extensions. ==="
