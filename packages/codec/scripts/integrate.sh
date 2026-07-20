#!/usr/bin/env bash
#
# One-command batch integration for newly-dropped protocol headers.
#   1. registers any unregistered header class in PacketHeaders.ts
#   2. clean-rebuilds the test tree (fails fast on real TS errors)
#   3. regenerates the per-fixture goldens + the _layergraph demux snapshot (UPDATE_GOLDEN=1)
#   4. runs the full unit suite and prints the tally
#
# Differential.spec mappings are NOT auto-generated (tshark↔field matching needs judgment); add them by
# hand in a later pass. New protocols are covered by byte round-trip + golden until then.
#
# Usage:  bash scripts/integrate.sh
set -uo pipefail
cd "$(dirname "$0")/.."

echo "== register-headers =="
node scripts/register-headers.js || exit 1

echo "== clean build:test =="
rm -rf dist-test
BUILD_OUT=$(npm run build:test 2>&1)
if echo "$BUILD_OUT" | grep -qiE "error TS"; then
    echo "!! TypeScript errors — aborting:"
    echo "$BUILD_OUT" | grep -iE "error TS" | head -20
    exit 1
fi

echo "== regenerate goldens + _layergraph snapshot =="
UPDATE_GOLDEN=1 node --test dist-test/test/units/Golden.spec.js dist-test/test/units/LayerGraph.spec.js >/dev/null 2>&1

echo "== full unit suite =="
node --test 'dist-test/test/units/**/*.spec.js' 2>&1 | grep -E "^ℹ (tests|pass|fail)|not ok"
