#!/bin/zsh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
APP="$PROJECT_ROOT/dist/NetGuard.app"
CONTENTS="$APP/Contents"
BUILD="$PROJECT_ROOT/dist/build"
ICONSET="$BUILD/AppIcon.iconset"

if [[ "$APP" != "$PROJECT_ROOT/dist/NetGuard.app" ]]; then
  print -u2 "Unexpected app path: $APP"
  exit 1
fi
rm -rf "$APP" "$BUILD"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources" "$BUILD" "$ICONSET"

swiftc -O -target arm64-apple-macosx12.0 \
  "$PROJECT_ROOT/app/NetGuardApp.swift" \
  -o "$CONTENTS/MacOS/NetGuard"

cp "$PROJECT_ROOT/app/Info.plist" "$CONTENTS/Info.plist"
cp "$PROJECT_ROOT/app/Privileged.applescript" "$CONTENTS/Resources/Privileged.applescript"
cp "$PROJECT_ROOT/app/netguard-gui-helper" "$CONTENTS/Resources/netguard-gui-helper"
chmod 0755 "$CONTENTS/Resources/netguard-gui-helper"

mkdir -p "$CONTENTS/Resources/netguard"
cp -R "$PROJECT_ROOT/bin" "$CONTENTS/Resources/netguard/bin"
cp -R "$PROJECT_ROOT/lib" "$CONTENTS/Resources/netguard/lib"
cp -R "$PROJECT_ROOT/web" "$CONTENTS/Resources/netguard/web"
cp -R "$PROJECT_ROOT/docs" "$CONTENTS/Resources/netguard/docs"
cp "$PROJECT_ROOT/README.md" "$CONTENTS/Resources/netguard/README.md"
chmod 0755 "$CONTENTS/Resources/netguard/bin/netguard" "$CONTENTS/Resources/netguard/bin/netguard-recovery"

swiftc -O "$PROJECT_ROOT/app/GenerateIcon.swift" -o "$BUILD/GenerateIcon"
"$BUILD/GenerateIcon" "$BUILD/icon_1024x1024.png"
for size in 16 32 128 256 512; do
  double=$((size * 2))
  sips -z "$size" "$size" "$BUILD/icon_1024x1024.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  sips -z "$double" "$double" "$BUILD/icon_1024x1024.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$CONTENTS/Resources/AppIcon.icns"

plutil -lint "$CONTENTS/Info.plist"
zsh -n "$CONTENTS/Resources/netguard-gui-helper"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
print "Built: $APP"
