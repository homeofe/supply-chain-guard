// Writes package.json + package-lock.json for a directory that installs the
// packed tarball with `npm ci`, pinned to exactly what this repository tested.
//
// `npm install <tarball>` resolves the package's runtime dependencies from the
// registry by their semver range, so `commander@^14` meant whatever 14.x was
// newest on the day, never checked against package-lock.json. The container
// image and the clean-room install in scripts/validate-package.sh both did
// that (OpenSSF Scorecard Pinned-Dependencies, code-scanning alerts 4 and 5).
//
// The lockfile written here records the tarball with its own sha512 and copies
// every runtime entry (not dev) of this repository's package-lock.json with its
// resolved URL and integrity, so `npm ci` installs the same bytes CI ran and
// refuses anything else. New dependency releases reach us through Dependabot,
// as a reviewed lockfile change, not through an install that happens to run.
//
// Usage: node scripts/clean-room-lockfile.mjs <tarball> <install-dir>
// The install directory is created if missing. The tarball must stay at the
// same path relative to it until `npm ci` has run.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const [tarballArg, dirArg] = process.argv.slice(2);
if (!tarballArg || !dirArg) {
  console.error("usage: node scripts/clean-room-lockfile.mjs <tarball> <install-dir>");
  process.exit(2);
}

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(repo, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(repo, "package-lock.json"), "utf8"));

const tarball = resolve(tarballArg);
const dir = resolve(dirArg);
const spec = `file:${relative(dir, tarball).split(sep).join("/")}`;
const integrity = `sha512-${createHash("sha512").update(readFileSync(tarball)).digest("base64")}`;

const ROOT_NAME = "scg-clean-room";
const packages = {
  "": { name: ROOT_NAME, version: "1.0.0", dependencies: { [pkg.name]: spec } },
  [`node_modules/${pkg.name}`]: {
    version: pkg.version,
    resolved: spec,
    integrity,
    license: pkg.license,
    dependencies: pkg.dependencies,
    bin: pkg.bin,
    engines: pkg.engines,
  },
};

let copied = 0;
for (const [path, entry] of Object.entries(lock.packages ?? {})) {
  if (path === "" || entry.dev || entry.devOptional || entry.link) continue;
  packages[path] = entry;
  copied++;
}

// Every declared runtime dependency must arrive pinned. An entry without an
// integrity hash would let npm ci accept whatever the registry serves.
for (const name of Object.keys(pkg.dependencies ?? {})) {
  const entry = packages[`node_modules/${name}`];
  if (!entry || !entry.integrity || !entry.resolved) {
    console.error(`clean-room-lockfile: runtime dependency ${name} has no pinned entry in package-lock.json`);
    process.exit(1);
  }
}

mkdirSync(dir, { recursive: true });
writeFileSync(
  join(dir, "package.json"),
  `${JSON.stringify({ name: ROOT_NAME, version: "1.0.0", private: true, dependencies: { [pkg.name]: spec } }, null, 2)}\n`,
);
writeFileSync(
  join(dir, "package-lock.json"),
  `${JSON.stringify({ name: ROOT_NAME, version: "1.0.0", lockfileVersion: 3, requires: true, packages }, null, 2)}\n`,
);
console.log(
  `clean-room lockfile: ${pkg.name}@${pkg.version} (${integrity.slice(0, 20)}...) plus ${copied} runtime package(s) from package-lock.json`,
);
