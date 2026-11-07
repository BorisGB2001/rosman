#!/usr/bin/env bash
# Выкатить новый релиз ROSMan.
# Перед запуском: обновите константу Version в internal/web/web.go и закоммитьте.
# Использование: scripts/release.sh v0.2.0
set -euo pipefail

VER="${1:?usage: scripts/release.sh vX.Y.Z}"
cd "$(dirname "$0")/.."

code_ver="v$(grep -oE 'Version = "[0-9.]+"' internal/web/web.go | grep -oE '[0-9.]+')"
if [ "$code_ver" != "$VER" ]; then
  echo "ВНИМАНИЕ: Version в коде = $code_ver, а релиз = $VER. Обновите internal/web/web.go." >&2
  exit 1
fi

echo "== сборка бинарников =="
rm -rf dist && mkdir -p dist
for pair in linux/amd64 linux/arm64 darwin/arm64 darwin/amd64; do
  os="${pair%/*}"; arch="${pair#*/}"
  echo "  $os/$arch"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "dist/rosman_${os}_${arch}" ./cmd/rosman
done

echo "== тег и релиз =="
git tag -a "$VER" -m "ROSMan $VER"
git push origin "$VER"
gh release create "$VER" --title "ROSMan $VER" --generate-notes dist/*
echo "готово: релиз $VER"
