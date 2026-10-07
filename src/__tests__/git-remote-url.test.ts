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

  it("F39: resolves dot segments and keeps only owner/repo of the path", () => {
    expect(publicGitRemoteUrl("https://github.com/o/r.git/../../x-access-token:abc")).toBeUndefined();
    expect(publicGitRemoteUrl("https://github.com/o/r.git/-/raw/main/file")).toBe("https://github.com/o/r.git");
    expect(publicGitRemoteUrl("https://github.com/o/x/%2e%2e/r")).toBe("https://github.com/o/r");
    expect(publicGitRemoteUrl("ssh://git@example.invalid/o/x/../r.git")).toBe("ssh://example.invalid/o/r.git");
    expect(publicGitRemoteUrl("https://github.com/o/r")).toBe("https://github.com/o/r");
    // GitLab subgroups are repository identity, not a file path: keep them.
    expect(publicGitRemoteUrl("https://gitlab.com/group/subgroup/r.git")).toBe("https://gitlab.com/group/subgroup/r.git");
    expect(publicGitRemoteUrl("git@gitlab.com:group/sub/r.git")).toBe("ssh://gitlab.com/group/sub/r.git");
  });

  it("F39: drops a remote whose path carries something credential-shaped", () => {
    expect(publicGitRemoteUrl("https://example.invalid/path/ghp_FAKETOKENINPATH/r.git")).toBeUndefined();
    expect(publicGitRemoteUrl("https://example.invalid/o/r.git/x-access-token:abc")).toBeUndefined();
    expect(publicGitRemoteUrl("git@example.invalid:o/glpat-FAKETOKEN/r.git")).toBeUndefined();
    // ordinary names must stay
    expect(publicGitRemoteUrl("git@github.com:homeofe/supply-chain-guard.git"))
      .toBe("ssh://github.com/homeofe/supply-chain-guard.git");
  });

  it("F39: SARIF omits versionControlProvenance instead of falling back to the local path", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-no-remote-"));
    created.push(dir);
    fs.writeFileSync(path.join(dir, "index.js"), "export const value = 1;\n");
    const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "pipe" });
    git("init", "-q");
    git("config", "user.name", "Test");
    git("config", "user.email", "test@example.invalid");
    git("add", "index.js");
    git("commit", "-qm", "initial");

    const report = await scan({ target: dir, format: "json", noHistory: true });
    expect(report.commit).toBeTruthy();
    expect(report.repositoryUri).toBeUndefined();
    const sarif = JSON.parse(formatReport(report, "sarif"));
    expect(sarif.runs[0].versionControlProvenance).toBeUndefined();
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
