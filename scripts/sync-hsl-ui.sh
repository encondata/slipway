#!/usr/bin/env bash
# Copies the HSL Suite kit (hackspacelabs-web/ui) into an app at a pinned release, or checks that the
# copy is untouched. Copy this script into each app that uses the kit.
#
#   scripts/sync-hsl-ui.sh ui-v0.1.0 web/src/hsl-ui     fetch that tag into web/src/hsl-ui
#   scripts/sync-hsl-ui.sh --check web/src/hsl-ui       fail if the copy differs from what was synced
#
# The copy records its tag and every file's SHA-256 in <dest>/HSL-UI.sum. Change the kit in
# hackspacelabs-web, tag a release (ui-vX.Y.Z), then sync; never edit the copy. HSL_UI_SOURCE=<folder>
# copies from a local checkout's ui/ instead of GitHub (for trying out an untagged change).
set -euo pipefail

repo=${HSL_UI_REPO:-encondata/hackspacelabs-web}
sumfile=HSL-UI.sum

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

sha() {
  if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# Every kit file in a folder, sorted, as "<sha256>  <path>" lines (the sum file itself excluded).
sums() {
  (cd "$1" && find . -type f ! -name "$sumfile" | LC_ALL=C sort | sed 's|^\./||' | while IFS= read -r f; do sha "$f"; done)
}

if [[ ${1:-} == --check ]]; then
  dest=${2:-}
  [[ -n $dest ]] || usage
  if [[ ! -f $dest/$sumfile ]]; then
    echo "$dest has no $sumfile: sync the kit with scripts/sync-hsl-ui.sh <tag> $dest" >&2
    exit 1
  fi
  tag=$(sed -n 's/^# tag //p' "$dest/$sumfile")
  if ! diff <(grep -v '^#' "$dest/$sumfile") <(sums "$dest") >/dev/null; then
    echo "The HSL Suite kit in $dest differs from $tag:" >&2
    diff <(grep -v '^#' "$dest/$sumfile") <(sums "$dest") >&2 || true
    echo "Change the kit in $repo, tag a release, and sync it again instead of editing the copy." >&2
    exit 1
  fi
  echo "$dest matches the HSL Suite kit $tag."
  exit 0
fi

tag=${1:-}
dest=${2:-}
[[ -n $tag && -n $dest ]] || usage
[[ $tag =~ ^ui-v[0-9]+\.[0-9]+\.[0-9]+$ || -n ${HSL_UI_SOURCE:-} ]] || {
  echo "Tags look like ui-v1.2.3 (got \"$tag\")." >&2
  exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [[ -n ${HSL_UI_SOURCE:-} ]]; then
  cp -R "$HSL_UI_SOURCE/." "$work/ui"
else
  curl -fsSL "https://codeload.github.com/$repo/tar.gz/refs/tags/$tag" -o "$work/kit.tgz"
  tar -xzf "$work/kit.tgz" -C "$work"
  mv "$work"/*/ui "$work/ui"
fi
[[ -f $work/ui/tokens.css && -f $work/ui/suite.js ]] || {
  echo "No HSL Suite kit (ui/tokens.css, ui/suite.js) at $tag." >&2
  exit 1
}
# The demo page stays in hackspacelabs-web; apps get the kit and its README.
rm -f "$work"/ui/demo.* "$work/ui/$sumfile"

rm -rf "$dest"
mkdir -p "$dest"
cp -R "$work/ui/." "$dest/"
{
  echo "# HSL Suite kit from $repo. Do not edit these files: see scripts/sync-hsl-ui.sh."
  echo "# tag $tag"
  sums "$dest"
} >"$dest/$sumfile"
echo "Synced the HSL Suite kit $tag into $dest ($(grep -vc '^#' "$dest/$sumfile") files)."
