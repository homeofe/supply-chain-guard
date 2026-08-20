#!/usr/bin/env bash
#
# Validate the PUBLISHED ARTIFACT, not the working tree.
#
# `npm test` proves the source passes its suite. It says nothing about whether
# the thing a consumer actually installs works, because the tarball is a
# different set of files: `files` in package.json ships dist plus five loose
# assets, and a build that emits nothing, an entry point that points at a
# missing file, a type declaration that never got generated or a bin mapping
# that is not executable all survive a green `npm test` and break on install.
#
# So this packs the repo, inspects what came out, installs the tarball into a
# directory that shares nothing with this checkout, and exercises the CLI and the
# programmatic entry point FROM THAT INSTALL. Everything it asserts is a promise
# package.json already makes, read out of package.json rather than hardcoded, so
# adding an export or renaming a bin cannot silently escape the check.
#
# Runs once per Node major in the CI compatibility matrix, which is what turns it
# from a packaging check into a compatibility check.
#
# Local use: bash scripts/validate-package.sh
#   Needs a POSIX shell, tar, and a writable temp dir. On Windows/MSYS set
#   SCG_VALIDATE_TMP to an explicit native path, because MSYS and native node
#   disagree about where /tmp is and node will not find what the shell wrote.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

fail=0
ok()   { echo "  [ok]   $1"; }
bad()  { echo "  [FAIL] $1"; fail=1; }
note() { echo "  ---    $1"; }

NAME=$(node -p "require('./package.json').name")
VERSION=$(node -p "require('./package.json').version")
echo "Validating packaged artifact: $NAME@$VERSION on node $(node -v)"
echo

# --- 1. the tarball must exist and be produced by the real pack path ----------
WORK="${SCG_VALIDATE_TMP:-$(mktemp -d)}"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

note "packing into $WORK"
TARBALL="$WORK/$(npm pack --silent --pack-destination "$WORK")"
if [ -f "$TARBALL" ]; then
  ok "npm pack produced $(basename "$TARBALL") ($(wc -c <"$TARBALL") bytes)"
else
  bad "npm pack produced no tarball"; exit 1
fi

LIST="$WORK/contents.txt"
# Listed from inside $WORK with a RELATIVE name on purpose: an absolute
# Windows path like C:/... reads as a remote host spec to MSYS tar, which then
# tries to resolve a host called "C". Harmless on the Linux runners, but it
# makes this script unusable locally, which is where it gets debugged.
( cd "$WORK" && tar -tzf "$(basename "$TARBALL")" ) | sed 's#^package/##' | sort >"$LIST"
note "$(wc -l <"$LIST" | tr -d ' ') entries in the tarball"

have() { grep -qxF "$1" "$LIST"; }

# --- 2. every generated file the manifest promises must be IN the tarball -----
# Read the promises out of package.json so this cannot drift from the manifest.
MAIN=$(node -p "require('./package.json').main || ''")
TYPES=$(node -p "require('./package.json').types || ''")

for f in "$MAIN" "$TYPES"; do
  [ -n "$f" ] || continue
  if have "$f"; then ok "manifest entry present in tarball: $f"
  else bad "manifest points at $f but the tarball does not contain it"; fi
done

while IFS= read -r binpath; do
  [ -n "$binpath" ] || continue
  if have "$binpath"; then ok "bin target present in tarball: $binpath"
  else bad "bin maps to $binpath but the tarball does not contain it"; fi
done < <(node -p "const b=require('./package.json').bin;Object.values(typeof b==='string'?{x:b}:(b||{})).join('\n')")

while IFS= read -r asset; do
  [ -n "$asset" ] || continue
  case "$asset" in *"*"*) continue ;; esac   # globs are checked via dist below
  if have "$asset"; then ok "declared asset present: $asset"
  else bad "files[] declares $asset but the tarball does not contain it"; fi
done < <(node -p "(require('./package.json').files||[]).join('\n')")

# A manifest-driven check is blind in one direction, and the mutation run proved
# it: every assertion above reads `files[]` and confirms the tarball contains what
# it declares, so DELETING an entry from `files[]` removes the file from the
# package AND removes the check that would have missed it. Caught by mutating
# package.json to drop policy-schema.json, which sailed through.
#
# So the runtime assets have a floor that does not come from the manifest. This
# list is duplicated on purpose. Adding to it should be a deliberate act, and
# removing from it should require saying why in a diff someone reviews.
for required in action.yml README.md LICENSE socket.yml policy-schema.json; do
  if have "$required"; then ok "required runtime asset ships: $required"
  else bad "required runtime asset MISSING from the tarball: $required"; fi
done

# A build that emitted nothing still packs a valid, useless tarball.
DIST_JS=$(grep -c '^dist/.*\.js$'   "$LIST" || true)
DIST_DTS=$(grep -c '^dist/.*\.d\.ts$' "$LIST" || true)
if [ "$DIST_JS"  -gt 20 ]; then ok "dist carries $DIST_JS compiled .js files"
else bad "dist carries only $DIST_JS .js files, the build did not emit"; fi
if [ "$DIST_DTS" -gt 20 ]; then ok "dist carries $DIST_DTS .d.ts type declarations"
else bad "dist carries only $DIST_DTS .d.ts files, declarations were not emitted"; fi

# --- 3. things that must NOT ship --------------------------------------------
# A scanner that ships its own test fixtures ships malicious sample payloads to
# every consumer, and the fixtures are large. Sources leaking is a smaller
# problem but still means the manifest is not doing what it says.
for pattern in '^src/' '^\.ai/' '^scripts/' '\.test\.ts$' '^tsconfig' '^feed\.json$' '^\.github/'; do
  n=$(grep -cE "$pattern" "$LIST" || true)
  if [ "$n" -eq 0 ]; then ok "tarball ships nothing matching $pattern"
  else bad "tarball ships $n entries matching $pattern"; grep -E "$pattern" "$LIST" | head -3 | sed 's/^/         /'; fi
done

# --- 4. install into a directory that shares nothing with this checkout -------
CLEAN="$WORK/clean"
mkdir -p "$CLEAN"
cd "$CLEAN"
npm init -y >/dev/null 2>&1
# --ignore-scripts on purpose: a consumer install must work without running any
# lifecycle script of ours, and this package declares none for install.
if npm install --silent --no-audit --no-fund --ignore-scripts "$TARBALL" >"$WORK/install.log" 2>&1; then
  ok "clean-room install succeeded from the tarball"
else
  bad "clean-room install failed"; tail -20 "$WORK/install.log" | sed 's/^/         /'; cd "$REPO"; exit 1
fi

INSTALLED="$CLEAN/node_modules/$NAME"
[ -d "$INSTALLED" ] && ok "installed at node_modules/$NAME" || bad "package not found under node_modules"

# --- 5. metadata survived the round trip -------------------------------------
I_NAME=$(node -p "require('$INSTALLED/package.json').name")
I_VER=$(node -p "require('$INSTALLED/package.json').version")
[ "$I_NAME" = "$NAME" ]    && ok "installed name matches: $I_NAME"       || bad "name drifted: $I_NAME vs $NAME"
[ "$I_VER"  = "$VERSION" ] && ok "installed version matches: $I_VER"     || bad "version drifted: $I_VER vs $VERSION"

I_ENG=$(node -p "JSON.stringify(require('$INSTALLED/package.json').engines||null)")
note "installed engines: $I_ENG"

# --- 6. the bin mapping actually resolves and runs ----------------------------
while IFS= read -r binname; do
  [ -n "$binname" ] || continue
  LINK="$CLEAN/node_modules/.bin/$binname"
  if [ -e "$LINK" ]; then ok "bin '$binname' linked into node_modules/.bin"
  else bad "bin '$binname' was not linked"; continue; fi
  if OUT=$("$LINK" --version 2>&1); then
    if [ "$(echo "$OUT" | tr -d '[:space:]')" = "$VERSION" ]; then
      ok "packaged CLI reports $OUT"
    else
      bad "packaged CLI reported '$OUT', package.json says '$VERSION'"
    fi
  else
    bad "packaged CLI failed to run: $OUT"
  fi
done < <(node -p "const b=require('./node_modules/$NAME/package.json').bin;Object.keys(typeof b==='string'?{'$NAME':b}:(b||{})).join('\n')")

# --- 7. the programmatic entry point loads and its exports are callable -------
# require() from the INSTALL, so a bad main/exports field fails here the way it
# would for a consumer, rather than resolving through the local source tree.
if node -e "
  const m = require('$NAME');
  const expected = ['scan', 'formatReport'];
  const missing = expected.filter((k) => typeof m[k] !== 'function');
  if (missing.length) { console.error('missing exports: ' + missing.join(', ')); process.exit(1); }
  console.log(Object.keys(m).length);
" >"$WORK/require.log" 2>&1; then
  ok "require('$NAME') resolved and exports $(cat "$WORK/require.log") names, including scan and formatReport"
else
  bad "require('$NAME') failed"; sed 's/^/         /' "$WORK/require.log"
fi

# --- 8. type declarations resolve the way a TypeScript consumer resolves them --
if [ -n "$TYPES" ] && [ -f "$INSTALLED/$TYPES" ]; then
  ok "type declarations present at $TYPES"
  # index.d.ts is a re-export barrel, so it carries `export { x } from "./y.js"`
  # and no `export declare` of its own. Assert on what a barrel actually looks
  # like, then follow one re-export to a leaf that does declare something, which
  # is what a consumer's compiler has to be able to do.
  if grep -qE '^export (\{|type |declare )' "$INSTALLED/$TYPES"; then
    ok "type declarations carry re-exports"
  else
    bad "$TYPES exports nothing recognisable"
  fi
  LEAF="$INSTALLED/dist/scanner.d.ts"
  if [ -f "$LEAF" ] && grep -qE 'declare (function|const|class) ' "$LEAF"; then
    ok "a re-exported leaf declaration resolves (dist/scanner.d.ts)"
  else
    bad "re-export target dist/scanner.d.ts is missing or declares nothing"
  fi
else
  bad "types field points at $TYPES which is not in the install"
fi

# --- 9. end to end: the packaged CLI scans a real directory --------------------
# The whole point of the artifact. A CLI that starts and then cannot complete a
# scan because a data file was left out of `files` passes every check above.
# Invoked as `scan <path> --format json`: this CLI is subcommand-driven, a bare
# path is an unknown command, and the flag is --format rather than --json. Both
# mistakes exit non-zero and look exactly like a broken artifact, so the
# invocation is worth stating precisely. --no-history keeps the check from
# writing .scg-history into the fixture it just created.
FIXTURE="$WORK/fixture"
mkdir -p "$FIXTURE"
printf '{\n  "name": "fixture",\n  "version": "1.0.0",\n  "dependencies": { "express": "4.18.2" }\n}\n' >"$FIXTURE/package.json"
BIN1=$(node -p "const b=require('$INSTALLED/package.json').bin;Object.keys(typeof b==='string'?{'$NAME':b}:(b||{}))[0]")
set +e
SCAN_OUT=$("$CLEAN/node_modules/.bin/$BIN1" scan "$FIXTURE" --format json --no-history 2>&1); SCAN_RC=$?
set -e
# Exit code is a findings verdict, not a health signal: this CLI exits non-zero
# when it finds something. Only a crash means the artifact is broken.
if echo "$SCAN_OUT" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{JSON.parse(d);process.exit(0)})" 2>/dev/null; then
  ok "packaged CLI completed a scan and emitted parseable JSON (exit $SCAN_RC)"
else
  bad "packaged CLI did not emit parseable JSON (exit $SCAN_RC)"
  echo "$SCAN_OUT" | head -15 | sed 's/^/         /'
fi

cd "$REPO"
echo
if [ "$fail" -eq 0 ]; then
  echo "Packaged artifact OK on node $(node -v): tarball contents, clean-room install, metadata, bin, entry point, declarations and an end-to-end scan all verified."
else
  echo "Packaged artifact validation FAILED on node $(node -v)."
fi
exit "$fail"
