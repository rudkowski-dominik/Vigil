#!/bin/zsh
# Builds build/Vigil.app (universal: Apple Silicon and Intel, ad-hoc signed) and a zip for GitHub Releases.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/Vigil.app
rm -rf build
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

for arch in arm64 x86_64; do
  swiftc -O \
    -target $arch-apple-macos14.0 \
    -o build/Vigil-$arch \
    Sources/Vigil/*.swift -lsqlite3
done
lipo -create -output "$APP/Contents/MacOS/Vigil" build/Vigil-arm64 build/Vigil-x86_64
rm build/Vigil-arm64 build/Vigil-x86_64

cp Resources/Info.plist "$APP/Contents/Info.plist"
codesign --force --sign - "$APP"

ditto -c -k --keepParent "$APP" build/Vigil.zip
echo "Built $APP"
