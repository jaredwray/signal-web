#!/usr/bin/env bash
# Fetches libsignal's protocol integration tests at the pinned commit and
# applies the minimal, mechanical transforms needed to run them in a browser.
# The transforms are implemented (and documented) in wasmify_upstream_tests.py.
set -euo pipefail
cd "$(dirname "$0")/.."

REV=e8cc2dddd578859b4a029c9c94670b24ce2b616a
DEST=crates/upstream-protocol-tests/tests
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

git -C "$TMP" init -q
git -C "$TMP" remote add origin https://github.com/signalapp/libsignal
git -C "$TMP" fetch -q --depth 1 origin "$REV"
git -C "$TMP" checkout -q FETCH_HEAD -- rust/protocol/tests

rm -rf "$DEST"
mkdir -p "$DEST"
cp -r "$TMP/rust/protocol/tests/." "$DEST/"
python3 scripts/wasmify_upstream_tests.py "$DEST"
echo "prepared upstream tests from libsignal@$REV in $DEST"
