#!/usr/bin/env bash
# Installs the npm that publishes this package, from a committed lockfile.
#
# The publish job needs npm >= 11.5.1 for OIDC trusted publishing, and an EXACT
# npm rather than whatever the runner's Node bundles, which moves with every Node
# patch release (docs/node-support.md, "The npm pin on the publish job"). It used
# to run `npm install --global npm@11.18.0`: pinned by version, but the tarball
# was never checked against a known hash, in the one job that holds the npm
# publish identity. `npm ci` checks it against the integrity recorded in
# .github/publish-toolchain/package-lock.json, which matched the registry's own
# dist.integrity for the pinned version when committed. The 143 packages npm
# bundles ship inside that one verified tarball; the publish-preflight job runs
# npm audit over them.
#
# Usage:
#   scripts/install-publish-npm.sh              install and verify (a rehearsal)
#   scripts/install-publish-npm.sh --add-to-path  also put it first on PATH for
#                                                 the following workflow steps
#
# The publish job and the publish-preflight job in ci.yml both run it, on the
# same Node major, so everything but the OIDC exchange is rehearsed on every
# pull request before a tag can reach it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLCHAIN="$ROOT/.github/publish-toolchain"
BIN="$TOOLCHAIN/node_modules/.bin"

want=$(node -p "require('$TOOLCHAIN/package-lock.json').packages['node_modules/npm'].version")

npm ci --prefix "$TOOLCHAIN" --ignore-scripts --no-audit --no-fund

got=$("$BIN/npm" --version)
if [ "$got" != "$want" ]; then
  echo "::error title=Publish npm::installed npm is $got, the lockfile pins $want"
  exit 1
fi
echo "publish npm $got installed from the lockfile (integrity-checked by npm ci)"

if [ "${1:-}" = "--add-to-path" ]; then
  if [ -z "${GITHUB_PATH:-}" ]; then
    echo "::error title=Publish npm::--add-to-path needs GITHUB_PATH (run inside GitHub Actions)"
    exit 1
  fi
  echo "$BIN" >> "$GITHUB_PATH"
fi
