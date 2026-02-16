#!/bin/bash
# Only reinstall extensions whose binary changed since last install
DERIVED="$HOME/Library/Developer/Xcode/DerivedData/Iris-*/Build/Products/Debug/Iris.app"
SYSEXT_DIR="/Library/SystemExtensions"

for ext in network endpoint proxy dns; do
  BUNDLE="com.wudan.iris.${ext}.extension"
  NEW=$(find $DERIVED -name "${BUNDLE}.systemextension" -print -quit 2>/dev/null)
  OLD=$(find $SYSEXT_DIR -name "${BUNDLE}.systemextension" -print -quit 2>/dev/null)

  if [ -z "$OLD" ] || [ -z "$NEW" ]; then
    echo "[$ext] needs install"
    continue
  fi

  NEW_HASH=$(shasum -a 256 "$NEW/Contents/MacOS/"* 2>/dev/null | awk '{print $1}')
  OLD_HASH=$(shasum -a 256 "$OLD/Contents/MacOS/"* 2>/dev/null | awk '{print $1}')

  if [ "$NEW_HASH" = "$OLD_HASH" ]; then
    echo "[$ext] unchanged — skipping"
  else
    echo "[$ext] changed — reinstalling"
    sudo systemextensionsctl uninstall 99HGW2AR62 "$BUNDLE"
  fi
done
