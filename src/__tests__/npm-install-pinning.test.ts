import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// Every npm command that downloads a package, in the files OpenSSF Scorecard's
// Pinned-Dependencies check reads (Dockerfiles, workflows, shell scripts), must
// be pinned by hash. Scorecard's rule (checks/raw/shell_download_validate.go):
// `npm install|i|install-test|update|ci` is a download, and only `npm ci` or an
// install from a git URL carrying a full commit hash counts as pinned.
//
// Three such installs were unpinned until 6.3.0 (code-scanning alerts 4, 5, 6):
// the container image and the clean-room test resolved `commander@^14` from the
// registry by range, and the publish job installed npm by version only. This
// test holds the repository to the rule instead of waiting for the next
// Scorecard run to notice.

const ROOT = path.resolve(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), "utf8");

const DOWNLOAD_VERBS = new Set(["install", "i", "install-test", "update", "ci"]);
const GIT_PINNED = /^(?:github:|git:\/\/|git\+https?:\/\/)[^#]+#[0-9a-f]{40}$/;
// Words that can stand before the command word itself. Scorecard parses the
// shell and only looks at a command whose FIRST word is npm; a text scan has to
// skip these to find that word, or `echo "... npm ... install ..."` reads as an
// install.
const LEADING = /^(?:RUN|run:|-|if|then|else|elif|do|while|until|!|time|sudo|exec|command|\(|\{)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** The unpinned npm download commands in one file's text, as trimmed lines. */
function unpinnedNpmDownloads(text: string): string[] {
  const found: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    // Comments are not commands: a whole-line comment, or a trailing one after
    // whitespace. Good enough for these files, which put no "#" inside quotes
    // on an npm line.
    const line = raw.replace(/(^|\s)#.*$/, "$1").trim();
    if (!line) continue;
    for (const command of line.split(/&&|\|\||;|\|/)) {
      const words = command.trim().split(/\s+/);
      let at = 0;
      while (at < words.length && (LEADING.test(words[at]) || ASSIGNMENT.test(words[at]))) at++;
      const head = (words[at] ?? "").replace(/^[({"']+|["')}]+$/g, "");
      if (head !== "npm" && !head.endsWith("/npm")) continue;
      const args = words.slice(at + 1).map((a) => a.replace(/^["'(]+|["')}]+$/g, ""));
      if (!args.some((a) => DOWNLOAD_VERBS.has(a))) continue;
      if (args.includes("ci")) continue;
      if (args.some((a) => GIT_PINNED.test(a))) continue;
      found.push(raw.trim());
    }
  }
  return found;
}

function scannedFiles(): string[] {
  const files: string[] = [];
  for (const name of fs.readdirSync(ROOT)) {
    if (/^Dockerfile/.test(name) || name.endsWith(".sh")) files.push(name);
  }
  for (const name of fs.readdirSync(path.join(ROOT, ".github", "workflows"))) {
    if (/\.ya?ml$/.test(name)) files.push(path.join(".github", "workflows", name));
  }
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
      const rel = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(rel);
      else if (entry.name.endsWith(".sh")) files.push(rel);
    }
  };
  walk("scripts");
  return files;
}

describe("the unpinned-download rule matches Scorecard's", () => {
  it("flags the three installs that were unpinned before 6.3.0", () => {
    for (const line of [
      "RUN npm install -g --ignore-scripts /tmp/supply-chain-guard-*.tgz && rm -f /tmp/supply-chain-guard-*.tgz",
      "          npm install --global --ignore-scripts npm@11.18.0",
      'if npm install --silent --no-audit --no-fund --ignore-scripts "$TARBALL" >"$WORK/install.log" 2>&1; then',
      "      - run: sudo NODE_ENV=ci npm i -g some-tool",
      "(cd sub && npm update)",
    ]) {
      expect(unpinnedNpmDownloads(line), line).toEqual([line.trim()]);
    }
  });

  it("passes npm ci, a commit-pinned git install, non-download commands and comments", () => {
    for (const line of [
      "RUN cd /opt/app && npm ci --ignore-scripts --no-audit --no-fund",
      'npm ci --prefix "$TOOLCHAIN" --ignore-scripts',
      `npm install git+https://github.com/o/r.git#${"a".repeat(40)}`,
      "npm pack --ignore-scripts --pack-destination /tmp",
      "npm run install:hooks",
      "# npm install -g supply-chain-guard",
      "      # used to be `npm install --global npm@11.18.0`",
      // Found by this test's first run: npm and install as words of a message.
      '            echo "::error title=Publish toolchain::The pinned npm the publish job uses did not install or verify."',
    ]) {
      expect(unpinnedNpmDownloads(line), line).toEqual([]);
    }
  });

  it("does not accept a git install pinned to a branch", () => {
    expect(unpinnedNpmDownloads("npm install git+https://github.com/o/r.git#main")).toHaveLength(1);
  });
});

describe("the repository pins every npm download", () => {
  const files = scannedFiles();

  it("reads the files Scorecard reads", () => {
    // Control: the scan is not vacuous.
    expect(files).toContain("Dockerfile");
    expect(files).toContain(path.join(".github", "workflows", "ci.yml"));
    expect(files).toContain(path.join("scripts", "validate-package.sh"));
    expect(files).toContain(path.join("scripts", "install-publish-npm.sh"));
  });

  it("has no unpinned npm download in any of them", () => {
    const hits = files.flatMap((f) => unpinnedNpmDownloads(read(f)).map((l) => `${f}: ${l}`));
    expect(hits).toEqual([]);
  });
});

describe("the publish job's npm", () => {
  const ci = read(".github/workflows/ci.yml");
  const job = (name: string) => {
    const start = ci.indexOf(`\n  ${name}:\n`);
    expect(start, name).toBeGreaterThan(0);
    const next = ci.slice(start + 1).search(/\n {2}[a-z][a-z0-9_-]*:\n/);
    return next < 0 ? ci.slice(start) : ci.slice(start, start + 1 + next);
  };
  const nodeVersions = (text: string) => [...text.matchAll(/node-version:\s*['"]?([0-9.]+)['"]?/g)].map((m) => m[1]);

  it("is installed by the lockfile script, on the same Node major the preflight rehearses", () => {
    const publish = job("publish");
    const preflight = job("publish-preflight");
    expect(publish).toContain("bash scripts/install-publish-npm.sh --add-to-path");
    expect(preflight).toContain("bash scripts/install-publish-npm.sh");
    expect(nodeVersions(preflight)).toEqual(nodeVersions(publish));
    expect(nodeVersions(publish)).toHaveLength(1);
  });

  it("is checked against the lockfile in the same step that publishes", () => {
    const step = job("publish").split("- name: Publish to npm")[1] ?? "";
    const check = step.indexOf('test "$(npm --version)" = "$want"');
    expect(check).toBeGreaterThan(0);
    expect(check).toBeLessThan(step.indexOf("npm publish"));
  });

  it("gates the required aggregator", () => {
    expect(job("build")).toMatch(/needs: \[[^\]]*publish-preflight[^\]]*\]/);
    expect(job("build")).toContain("PREFLIGHT_RESULT");
  });

  it("is an exact pin with an integrity hash, at or above the trusted-publishing floor", () => {
    const manifest = JSON.parse(read(".github/publish-toolchain/package.json"));
    const lock = JSON.parse(read(".github/publish-toolchain/package-lock.json"));
    const entry = lock.packages["node_modules/npm"];
    expect(manifest.dependencies.npm).toMatch(/^\d+\.\d+\.\d+$/);
    expect(entry.version).toBe(manifest.dependencies.npm);
    expect(entry.integrity).toMatch(/^sha512-[A-Za-z0-9+/]{86}==$/);
    expect(entry.resolved).toBe(`https://registry.npmjs.org/npm/-/npm-${entry.version}.tgz`);
    const [maj, min, pat] = entry.version.split(".").map(Number);
    expect(maj > 11 || (maj === 11 && (min > 5 || (min === 5 && pat >= 1)))).toBe(true);
  });
});

describe("clean-room-lockfile.mjs", () => {
  it("records the tarball's sha512 and exactly the runtime entries of package-lock.json", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-cleanroom-"));
    try {
      const tarball = path.join(dir, "pkg.tgz");
      fs.writeFileSync(tarball, "not really a tarball, only hashed");
      const out = path.join(dir, "install");
      execFileSync(process.execPath, [path.join(ROOT, "scripts", "clean-room-lockfile.mjs"), tarball, out]);

      const pkg = JSON.parse(read("package.json"));
      const repoLock = JSON.parse(read("package-lock.json"));
      const lock = JSON.parse(fs.readFileSync(path.join(out, "package-lock.json"), "utf8"));
      const self = lock.packages[`node_modules/${pkg.name}`];
      const sha = createHash("sha512").update(fs.readFileSync(tarball)).digest("base64");

      expect(self.resolved).toBe("file:../pkg.tgz");
      expect(self.integrity).toBe(`sha512-${sha}`);
      expect(lock.packages[""].dependencies).toEqual({ [pkg.name]: "file:../pkg.tgz" });

      const runtime = Object.entries(repoLock.packages as Record<string, { dev?: boolean; devOptional?: boolean; link?: boolean }>)
        .filter(([p, e]) => p !== "" && !e.dev && !e.devOptional && !e.link)
        .map(([p]) => p);
      const copied = Object.keys(lock.packages).filter((p) => p !== "" && p !== `node_modules/${pkg.name}`);
      expect(copied.sort()).toEqual(runtime.sort());
      for (const dep of Object.keys(pkg.dependencies)) {
        expect(lock.packages[`node_modules/${dep}`]).toEqual(repoLock.packages[`node_modules/${dep}`]);
      }
      // Control: dev tooling never reaches the install.
      expect(lock.packages["node_modules/vitest"]).toBeUndefined();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
