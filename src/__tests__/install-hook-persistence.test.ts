/**
 * INSTALL_HOOK_PERSISTENCE_WRITE (T-019, tranche 2).
 *
 * An install hook that registers launchd, systemd, cron, a scheduled task, a
 * Windows Run key, a Startup entry or an auto-imported .pth is scheduling code
 * to run again later, independently of the package being installed. That is how
 * a one-shot credential stealer becomes a permanent re-harvester.
 *
 * Scope is the point. The rule only reads the six package.json install-script
 * strings this scanner already reads. The same commands in ordinary source
 * belong to any service manager or devops tool and would false-positive
 * constantly, so the narrow scope is what keeps the rule cheap.
 *
 * The last test pins the honest limit: the hook string is all the scanner sees,
 * so indirection through a script file defeats it. That is a real boundary, not
 * an oversight, and it is stated in the CHANGELOG.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { analyzeInstallHooks } from "../install-hook-scanner.js";
import { scan } from "../scanner.js";

const RULE = "INSTALL_HOOK_PERSISTENCE_WRITE";
const hits = (script: string, hook = "postinstall") =>
  analyzeInstallHooks({ [hook]: script }, "package.json").filter(
    (f) => f.rule === RULE,
  );

let tmpRoot: string;
beforeAll(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "scg-ihp-"));
});
afterAll(() => {
  if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
});

describe("persistence mechanisms are detected", () => {
  const cases: [string, string][] = [
    ["macOS launchd", "cp a.plist ~/Library/LaunchAgents/x.plist && launchctl load -w ~/Library/LaunchAgents/x.plist"],
    ["systemd user unit", "systemctl --user daemon-reload && systemctl --user enable --now x.service"],
    ["systemd system unit", "cp x.service /etc/systemd/system/ && systemctl enable x"],
    ["cron", "(crontab -l; echo '*/5 * * * * /tmp/x.sh') | crontab -"],
    ["cron drop-in", "cp x /etc/cron.d/x"],
    ["Windows scheduled task", "schtasks /create /tn Updater /tr C:\\\\x.exe /sc onlogon"],
    ["Windows Run key", "reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v X /d C:\\\\x.exe"],
    ["Startup folder", "copy x.lnk \"%APPDATA%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\""],
    ["python auto-import pth", "cp hook.pth /usr/lib/python3/site-packages/hook.pth"],
  ];

  for (const [label, script] of cases) {
    it(`fires on ${label}`, () => {
      const found = hits(script);
      expect(found).toHaveLength(1);
      expect(found[0].severity).toBe("high");
    });
  }

  it("fires on every install-script hook name, not just postinstall", () => {
    for (const hook of ["preinstall", "install", "prepare", "postuninstall"]) {
      expect(hits("launchctl load -w x.plist", hook)).toHaveLength(1);
    }
  });

  it("stays high rather than critical, so critical-gated pipelines are unaffected", () => {
    // A package that legitimately registers a service exists, even if it is
    // rare. Reporting at high keeps `--fail-on critical` consumers untouched
    // while still surfacing it.
    expect(hits("launchctl load x")[0].severity).toBe("high");
  });
});

describe("ordinary build hooks stay clean", () => {
  const benign = [
    "node scripts/build.js",
    "tsc",
    "npm run build && npm run test",
    "patch-package",
    "husky install",
    "node-gyp rebuild",
    "prisma generate",
    "echo 'thanks for installing'",
    // Restarting a service is not registering persistence.
    "systemctl restart nginx",
    // "install" as a word, and a path that merely mentions run.
    "npm install --production && node ./scripts/run-migrations.js",
  ];

  for (const script of benign) {
    it(`ignores: ${script}`, () => {
      expect(hits(script)).toEqual([]);
    });
  }
});

describe("scan routing and the honest limit", () => {
  function fixture(name: string, files: Record<string, string>): string {
    const dir = path.join(tmpRoot, name);
    fs.mkdirSync(dir, { recursive: true });
    for (const [rel, body] of Object.entries(files)) {
      const target = path.join(dir, rel);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, body);
    }
    return dir;
  }

  it("reports through a real directory scan", async () => {
    const dir = fixture("inline", {
      "package.json": JSON.stringify({
        name: "fx",
        version: "1.0.0",
        scripts: { postinstall: "systemctl --user enable --now updater.service" },
      }),
    });

    const report = await scan({ target: dir, format: "json" });
    const found = report.findings.filter((f) => f.rule === RULE);

    expect(found).toHaveLength(1);
    expect(found[0].file).toBe("package.json");
  });

  it("does NOT see persistence hidden behind a script file", async () => {
    // The honest boundary. The hook string is all this rule reads, so calling
    // out to a file defeats it. Detecting that needs the script's CONTENTS,
    // which is a different rule against a different input. Recorded rather than
    // papered over; if this ever starts passing, the limit has been lifted and
    // the CHANGELOG claim should be updated with it.
    const dir = fixture("indirect", {
      "package.json": JSON.stringify({
        name: "fx",
        version: "1.0.0",
        scripts: { postinstall: "node scripts/configure.js" },
      }),
      "scripts/configure.js":
        "require('child_process').execSync('systemctl --user enable --now updater.service');\n",
    });

    const report = await scan({ target: dir, format: "json" });
    expect(report.findings.filter((f) => f.rule === RULE)).toEqual([]);
  });

  it("leaves an ordinary package clean", async () => {
    const dir = fixture("clean", {
      "package.json": JSON.stringify({
        name: "fx",
        version: "1.0.0",
        scripts: { build: "tsc", postinstall: "node scripts/build.js" },
      }),
      "scripts/build.js": "console.log('build');\n",
    });

    const report = await scan({ target: dir, format: "json" });
    expect(report.findings.filter((f) => f.rule === RULE)).toEqual([]);
  });
});
