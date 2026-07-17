import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock node:https before importing the module (see vscode-registry.test.ts).
vi.mock("node:https", () => {
  const mockGet = vi.fn();
  return { default: { get: mockGet }, get: mockGet };
});

import * as https from "node:https";
import { checkRepositoryClaim, parseRepositoryField } from "../npm-scanner.js";
import type { Finding } from "../types.js";

/**
 * Route mocked https.get responses by requested URL. router(url) returns the
 * response for that URL; default 404. The flag path fetches package.json AND
 * the workspace manifests, so tests must answer per-URL.
 */
function mockHttp(router: (url: string) => { status: number; body?: string }): void {
  const mockedGet = https.get as unknown as ReturnType<typeof vi.fn>;
  mockedGet.mockImplementation((url: unknown, _opts: unknown, cb: (res: unknown) => void) => {
    const spec = router(String(url));
    const res = {
      statusCode: spec.status,
      resume: () => {},
      on: (event: string, handler: (chunk?: Buffer) => void) => {
        if (event === "data" && spec.status === 200 && spec.body !== undefined) handler(Buffer.from(spec.body));
        if (event === "end" && spec.status === 200) handler();
        return res;
      },
    };
    cb(res);
    return { on: () => {}, destroy: () => {}, setTimeout: () => {} };
  });
}

/** package.json returns `body`; workspace manifests 404 (not a monorepo). */
function repoWithPackageJson(body: string): (url: string) => { status: number; body?: string } {
  return (url) => (url.endsWith("/package.json") ? { status: 200, body } : { status: 404 });
}

describe("parseRepositoryField", () => {
  it("normalizes the common repository shapes to github owner/repo", () => {
    expect(parseRepositoryField("https://github.com/lodash/lodash.git")).toEqual({ owner: "lodash", repo: "lodash" });
    expect(parseRepositoryField("git+https://github.com/foo/bar.git")).toEqual({ owner: "foo", repo: "bar" });
    expect(parseRepositoryField("github:foo/bar")).toEqual({ owner: "foo", repo: "bar" });
    expect(parseRepositoryField("foo/bar")).toEqual({ owner: "foo", repo: "bar" });
    expect(parseRepositoryField({ type: "git", url: "https://github.com/a/b", directory: "packages/c" }))
      .toEqual({ owner: "a", repo: "b", directory: "packages/c" });
  });

  it("returns null for non-GitHub and missing repositories", () => {
    expect(parseRepositoryField("https://gitlab.com/x/y")).toBeNull();
    expect(parseRepositoryField(undefined)).toBeNull();
    expect(parseRepositoryField({})).toBeNull();
  });
});

describe("checkRepositoryClaim (starjacking)", () => {
  let findings: Finding[];
  beforeEach(() => {
    findings = [];
    (https.get as unknown as ReturnType<typeof vi.fn>).mockReset();
  });

  it("flags a package whose claimed repo publishes a different, unrelated package", async () => {
    mockHttp(repoWithPackageJson(JSON.stringify({ name: "express" })));
    await checkRepositoryClaim("evil-wallet-stealer", { repository: "https://github.com/expressjs/express" }, findings);
    const f = findings.find((x) => x.rule === "STARJACKING_SUSPECTED");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  it("does NOT flag when the repo publishes the same package", async () => {
    mockHttp(repoWithPackageJson(JSON.stringify({ name: "left-pad" })));
    await checkRepositoryClaim("left-pad", { repository: "https://github.com/stevemao/left-pad" }, findings);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a related name (same project)", async () => {
    mockHttp(repoWithPackageJson(JSON.stringify({ name: "coolthing-project" })));
    await checkRepositoryClaim("coolthing-lib", { repository: "https://github.com/someorg/coolthing-project" }, findings);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag when the package scope matches the repo owner (org ownership)", async () => {
    // pnpm/lerna monorepo layout: @acme/core from github.com/acme/platform.
    // Skipped before any fetch by the scope==owner ownership signal.
    await checkRepositoryClaim("@acme/core", { repository: "https://github.com/acme/platform" }, findings);
    expect(findings).toHaveLength(0);
    expect(https.get).not.toHaveBeenCalled();
  });

  it("does NOT flag a private (monorepo-root) package.json even with a different name", async () => {
    mockHttp(repoWithPackageJson(JSON.stringify({ name: "the-platform", private: true })));
    await checkRepositoryClaim("published-widget", { repository: "https://github.com/vendor/the-platform" }, findings);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag when the pnpm-workspace.yaml manifest exists (monorepo)", async () => {
    mockHttp((url) => {
      if (url.endsWith("/package.json")) return { status: 200, body: JSON.stringify({ name: "the-platform" }) };
      if (url.endsWith("/pnpm-workspace.yaml")) return { status: 200, body: "packages:\n  - 'packages/*'\n" };
      return { status: 404 };
    });
    await checkRepositoryClaim("published-widget", { repository: "https://github.com/vendor/the-platform" }, findings);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag an all-generic package name (cannot judge relatedness)", async () => {
    // "core" reduces to no significant token -> unrelatedness is unprovable -> skip (no fetch).
    await checkRepositoryClaim("core", { repository: "https://github.com/facebook/react" }, findings);
    expect(findings).toHaveLength(0);
    expect(https.get).not.toHaveBeenCalled();
  });

  it("does NOT flag a monorepo (workspaces present)", async () => {
    mockHttp(repoWithPackageJson(JSON.stringify({ name: "babel", workspaces: ["packages/*"] })));
    await checkRepositoryClaim("babel-thing", { repository: "https://github.com/babel/babel" }, findings);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a monorepo subdirectory (repository.directory set)", async () => {
    await checkRepositoryClaim("@scope/pkg", { repository: { url: "https://github.com/vendor/mono", directory: "packages/pkg" } }, findings);
    expect(findings).toHaveLength(0);
    expect(https.get).not.toHaveBeenCalled();
  });

  it("does NOT flag when the repo is unfetchable (404 / private / network)", async () => {
    mockHttp(() => ({ status: 404 }));
    await checkRepositoryClaim("some-widget", { repository: "https://github.com/ghost/repo" }, findings);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag a non-GitHub repository host", async () => {
    await checkRepositoryClaim("some-widget", { repository: "https://gitlab.com/x/y" }, findings);
    expect(findings).toHaveLength(0);
    expect(https.get).not.toHaveBeenCalled();
  });

  it("does NOT flag when there is no repository field", async () => {
    await checkRepositoryClaim("some-widget", {}, findings);
    expect(findings).toHaveLength(0);
    expect(https.get).not.toHaveBeenCalled();
  });

  it("does NOT flag when the repo package.json is malformed", async () => {
    mockHttp(repoWithPackageJson("{ not json"));
    await checkRepositoryClaim("some-widget", { repository: "https://github.com/a/b" }, findings);
    expect(findings).toHaveLength(0);
  });
});
