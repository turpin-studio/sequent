#!/bin/sh
# Check a built disk image: it mounts, holds the signed app and a shortcut
# to Applications, has its background, and the app in it reads the CDJs as
# it should. The release pipeline runs this on every build:
#
#   make dmg && tools/check_dmg.sh build/Sequent.dmg
set -eu
dmg=$1
here=$(cd "$(dirname "$0")" && pwd)
mount=$(mktemp -d)
hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$mount" "$dmg" >/dev/null
trap 'hdiutil detach -quiet "$mount" || hdiutil detach -force -quiet "$mount"' EXIT
test -d "$mount/Sequent.app" || { echo "no Sequent.app in the image"; exit 1; }
test "$(readlink "$mount/Applications")" = /Applications || { echo "no shortcut to Applications"; exit 1; }
test -f "$mount/.background.tiff" || { echo "no background"; exit 1; }
test -f "$mount/.DS_Store" || { echo "no window layout"; exit 1; }
codesign --verify --deep --strict "$mount/Sequent.app"
python3 "$here/check_app.py" "$mount/Sequent.app"
echo "ok: $(basename "$dmg") mounts, with the signed app, Applications, its background and layout"
