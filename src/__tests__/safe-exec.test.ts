import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resolveExecutable } from "../safe-exec.js";
import { scan } from "../scanner.js";
import { runInstallGuard } from "../install-guard.js";

const isWin = process.platform === "win32";

/**
 * Write a fake tool named `name` into `dir` that, when run, drops MARKER into
 * `dir`. On Windows it is a .bat (cmd.exe runs it from the current directory
 * by default); on POSIX an executable shell script.
 */
function plantTool(dir: string, name: string): string {
  const marker = path.join(dir, "MARKER");
  if (isWin) {
    fs.writeFileSync(path.join(dir, `${name}.bat`), `@echo off\r\necho planted> "%~dp0MARKER"\r\n`);
    fs.writeFileSync(path.join(dir, `${name}.cmd`), `@echo off\r\necho planted> "%~dp0MARKER"\r\n`);
  } else {
    const file = path.join(dir, name);
    fs.writeFileSync(file, `#!/bin/sh\ntouch "${marker}"\n`);
    fs.chmodSync(file, 0o755);
  }
  return marker;
}

describe("resolveExecutable", () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-safe-exec-"));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function tool(dir: string, file: string): string {
    fs.mkdirSync(dir, { recursive: true });
    const full = path.join(dir, file);
    fs.writeFileSync(full, isWin ? "" : "#!/bin/sh\n");
    if (!isWin) fs.chmodSync(full, 0o755);
    return full;
  }

  const exe = isWin ? "faketool.exe" : "faketool";

  it("returns the absolute path from an absolute PATH entry", () => {
    const dir = path.join(root, "bin");
    const expected = tool(dir, exe);
    expect(resolveExecutable("faketool", { env: { PATH: dir, PATHEXT: ".EXE" } })).toBe(expected);
  });

  it("never searches empty or relative PATH entries, which stand for the current directory", () => {
    const sep = isWin ? ";" : ":";
    tool(path.join(root, "rel"), exe);
    const env = { PATH: ["", ".", "rel", "./rel"].join(sep), PATHEXT: ".EXE" };
    const cwd = process.cwd();
    try {
      process.chdir(root);
      tool(root, exe);
      expect(resolveExecutable("faketool", { env })).toBeUndefined();
    } finally {
      process.chdir(cwd);
    }
  });

  // GHSA-gqpg-9mjx-pv4w: npx / npm exec / npm run put node_modules/.bin of the
  // start directory and every parent at the front of PATH, as absolute entries.
  it("skips node_modules/.bin entries even though they are absolute", () => {
    const sep = isWin ? ";" : ":";
    const planted = path.join(root, "checkout", "node_modules", ".bin");
    const parent = path.join(root, "node_modules", ".bin");
    tool(planted, exe);
    tool(parent, exe);
    const real = tool(path.join(root, "bin"), exe);
    const env = { PATH: [planted, planted + path.sep, parent, path.join(root, "bin")].join(sep), PATHEXT: ".EXE" };
    expect(resolveExecutable("faketool", { env })).toBe(real);
    expect(resolveExecutable("faketool", { env: { PATH: [planted, parent].join(sep), PATHEXT: ".EXE" } })).toBeUndefined();
  });

  it("still searches directories that only look similar to node_modules/.bin", () => {
    const sep = isWin ? ";" : ":";
    const similar = [
      path.join(root, "node_modules", ".bin-tools"),
      path.join(root, "node_modules", "pkg", "bin"),
      path.join(root, "my_node_modules", ".bin"),
    ];
    for (const dir of similar) {
      const expected = tool(dir, exe);
      expect(resolveExecutable("faketool", { env: { PATH: [dir].join(sep), PATHEXT: ".EXE" } })).toBe(expected);
    }
  });

  it.runIf(isWin)("matches node_modules\\.bin case-insensitively and with either separator on Windows", () => {
    const planted = path.join(root, "checkout", "Node_Modules", ".BIN");
    tool(planted, "faketool.exe");
    const forward = planted.replace(/\\/g, "/");
    expect(resolveExecutable("faketool", { env: { PATH: planted, PATHEXT: ".EXE" } })).toBeUndefined();
    expect(resolveExecutable("faketool", { env: { PATH: forward, PATHEXT: ".EXE" } })).toBeUndefined();
  });

  it("refuses anything that is not a bare file name", () => {
    const dir = path.join(root, "bin");
    tool(dir, exe);
    const env = { PATH: dir, PATHEXT: ".EXE" };
    expect(resolveExecutable(path.join(dir, "faketool"), { env })).toBeUndefined();
    expect(resolveExecutable("../bin/faketool", { env })).toBeUndefined();
    expect(resolveExecutable("", { env })).toBeUndefined();
  });

  it.runIf(isWin)("follows PATHEXT order and skips .cmd/.bat unless the caller can quote for cmd.exe", () => {
    const dir = path.join(root, "bin");
    const cmd = tool(dir, "faketool.cmd");
    const env = { Path: dir, PATHEXT: ".COM;.EXE;.BAT;.CMD" };
    expect(resolveExecutable("faketool", { env })).toBeUndefined();
    expect(resolveExecutable("faketool", { env, allowShellScripts: true })).toBe(cmd);
    const exePath = tool(dir, "faketool.exe");
    expect(resolveExecutable("faketool", { env, allowShellScripts: true })).toBe(exePath);
  });

  it.runIf(isWin)("never picks the extensionless file (npm ships a POSIX script named plain npm)", () => {
    const dir = path.join(root, "bin");
    tool(dir, "faketool");
    expect(resolveExecutable("faketool", { env: { PATH: dir, PATHEXT: ".EXE;.CMD" }, allowShellScripts: true }))
      .toBeUndefined();
  });
});

// Advisory regression: a tool planted in the scanned directory (or in the
// directory the install guard runs from) must never be executed.
describe("tools are never run from the current or scanned directory", () => {
  let root: string;
  let savedPath: string | undefined;
  let savedNoCwd: string | undefined;
  const pathKey = isWin ? (Object.keys(process.env).find((k) => k.toUpperCase() === "PATH") ?? "Path") : "PATH";

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-planted-"));
    savedPath = process.env[pathKey];
    savedNoCwd = process.env.NoDefaultCurrentDirectoryInExePath;
    // The attack conditions. Windows: the default, where cmd.exe and
    // CreateProcess search the current directory first. POSIX: an empty
    // PATH entry, which the shell and execvp read as the current directory.
    delete process.env.NoDefaultCurrentDirectoryInExePath;
    if (!isWin) process.env.PATH = `:${savedPath ?? ""}`;
  });
  afterEach(() => {
    if (savedPath === undefined) delete process.env[pathKey];
    else process.env[pathKey] = savedPath;
    if (savedNoCwd === undefined) delete process.env.NoDefaultCurrentDirectoryInExePath;
    else process.env.NoDefaultCurrentDirectoryInExePath = savedNoCwd;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("scan does not run a git planted in the scanned directory", async () => {
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    const marker = plantTool(root, "git");
    const cwd = process.cwd();
    try {
      // `scan .` from inside the hostile checkout is the common way to run it.
      process.chdir(root);
      await scan({ target: root, format: "json" });
    } finally {
      process.chdir(cwd);
    }
    expect(fs.existsSync(marker), "the planted git ran during scan").toBe(false);
  });

  it("install guard does not run a package manager planted in the current directory", () => {
    const marker = plantTool(root, "npm");
    const cwd = process.cwd();
    try {
      process.chdir(root);
      runInstallGuard("npm", ["--version"], { feed: [], log: () => {} });
    } catch {
      // npm missing from PATH is fine here; only the marker matters.
    } finally {
      process.chdir(cwd);
    }
    expect(fs.existsSync(marker), "the planted npm ran").toBe(false);
  });
});

// GHSA-gqpg-9mjx-pv4w regression: started through npx from inside the
// checkout, npm puts <checkout>/node_modules/.bin first on PATH. A git or
// package manager committed there must not run. POSIX only: on Windows the
// planted file would have to be a real .exe, and the resolver tests above
// cover the Windows path forms.
describe.skipIf(isWin)("tools are never run from a node_modules/.bin on PATH", () => {
  let root: string;
  let savedPath: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-npx-bin-"));
    savedPath = process.env.PATH;
    // What npx does when started in root: its node_modules/.bin goes first.
    process.env.PATH = `${path.join(root, "node_modules", ".bin")}:${savedPath ?? ""}`;
  });
  afterEach(() => {
    if (savedPath === undefined) delete process.env.PATH;
    else process.env.PATH = savedPath;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("scan does not run a git committed to node_modules/.bin of the scanned checkout", async () => {
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    // A .git directory as in any real checkout, so the git history check runs too.
    fs.mkdirSync(path.join(root, ".git"));
    const bin = path.join(root, "node_modules", ".bin");
    fs.mkdirSync(bin, { recursive: true });
    const marker = plantTool(bin, "git");
    const cwd = process.cwd();
    try {
      process.chdir(root);
      await scan({ target: root, format: "json" });
    } finally {
      process.chdir(cwd);
    }
    expect(fs.existsSync(marker), "the git from node_modules/.bin ran during scan").toBe(false);
  });

  it("install guard does not run a package manager from node_modules/.bin", () => {
    const bin = path.join(root, "node_modules", ".bin");
    fs.mkdirSync(bin, { recursive: true });
    const marker = plantTool(bin, "npm");
    const cwd = process.cwd();
    try {
      process.chdir(root);
      runInstallGuard("npm", ["--version"], { feed: [], log: () => {} });
    } catch {
      // npm missing from PATH is fine here; only the marker matters.
    } finally {
      process.chdir(cwd);
    }
    expect(fs.existsSync(marker), "the npm from node_modules/.bin ran").toBe(false);
  });
});
