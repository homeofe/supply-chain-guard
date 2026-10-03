import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { publicGitRemoteUrl } from "../git-remote-url.js";
import { scan } from "../scanner.js";
import { formatReport } from "../reporter.js";

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("Git remote report boundary", () => {
  it("drops URL user information, query, and fragment", () => {
    expect(publicGitRemoteUrl("https://reader:sample-secret@example.invalid/repo.git?key=value#part"))
      .toBe("https://example.invalid/repo.git");
    expect(publicGitRemoteUrl("sample-secret@example.invalid:owner/repo.git"))
      .toBe("ssh://example.invalid/owner/repo.git");
  });

  it("keeps a synthetic credential out of both JSON and SARIF scan output", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-remote-report-"));
    created.push(dir);
    fs.writeFileSync(path.join(dir, "index.js"), "export const value = 1;\n");
    const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "pipe" });
    git("init", "-q");
    git("config", "user.name", "Test");
    git("config", "user.email", "test@example.invalid");
    git("add", "index.js");
    git("commit", "-qm", "initial");
    const credential = "AUDIT_FAKE_CREDENTIAL";
    git("remote", "add", "origin", `https://reader:${credential}@example.invalid/repo.git?key=${credential}`);

    const report = await scan({ target: dir, format: "json", noHistory: true });
    expect(report.repositoryUri).toBe("https://example.invalid/repo.git");
    expect(formatReport(report, "json")).not.toContain(credential);
    expect(formatReport(report, "sarif")).not.toContain(credential);
  });
});
