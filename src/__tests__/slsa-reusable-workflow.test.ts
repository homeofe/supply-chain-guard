/**
 * Issue 190's fix required the `npm publish --provenance` step and the
 * `id-token: write` permission to resolve to the same job. That is right for a
 * job that publishes from its own steps, and wrong for the way a great many
 * projects actually publish.
 *
 * A caller job holds the permission and does nothing else but `uses:` a
 * reusable workflow; the callee runs the publish. GitHub passes the CALLER's
 * permissions to the callee, so `id-token: write` really is in effect at the
 * publish step and that configuration really does mint Sigstore provenance.
 * Requiring both signals in one job's own steps rejected it - a false negative,
 * which is the safe direction of error but still a wrong answer, and silently
 * under-grading is the same class of defect as silently over-grading.
 *
 * The bound that keeps this from becoming over-grading is that ONLY LOCAL
 * callees are resolved. A remote `owner/repo/.github/workflows/x.yml@ref` cannot
 * be read from the checkout, so crediting it would credit a workflow nobody has
 * looked at. The second test is the one that matters: it pins the refusal.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getSLSALevel } from "../slsa-verifier.js";

const CALLEE = [
  "name: reusable-publish",
  "on:",
  "  workflow_call:",
  "jobs:",
  "  publish:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - run: npm publish --provenance --access public",
  "",
].join("\n");

function caller(usesRef: string): string {
  return [
    "name: release",
    "on:",
    "  push:",
    '    tags: ["v*"]',
    "jobs:",
    "  call-publish:",
    "    permissions:",
    "      id-token: write",
    "      contents: read",
    `    uses: ${usesRef}`,
    "",
  ].join("\n");
}

describe("npm provenance published through a reusable workflow", () => {
  let dir: string;
  let wf: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-reuse-"));
    wf = path.join(dir, ".github", "workflows");
    fs.mkdirSync(wf, { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), '{"name":"x","version":"1.0.0"}');
    fs.writeFileSync(path.join(wf, "reusable-publish.yml"), CALLEE);
  });

  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("credits a LOCAL callee, because the caller's id-token is in effect there", () => {
    fs.writeFileSync(path.join(wf, "release.yml"), caller("./.github/workflows/reusable-publish.yml"));
    expect(getSLSALevel(dir)).toBe(3);
  });

  it("refuses a REMOTE callee, because nothing in this checkout has read it", () => {
    // The local file of the same name is present on purpose: a lookup that
    // collapsed the remote reference to a basename would match it and credit a
    // workflow that has nothing to do with this repository.
    fs.writeFileSync(
      path.join(wf, "release.yml"),
      caller("someorg/somerepo/.github/workflows/reusable-publish.yml@v1"),
    );
    expect(getSLSALevel(dir)).toBeLessThan(3);
  });

  it("still refuses when the caller holds no id-token permission", () => {
    // Control for the first test: without this, "credits a local callee" would
    // pass just as well for an implementation that credited any local callee at
    // all, permission or not.
    fs.writeFileSync(
      path.join(wf, "release.yml"),
      [
        "name: release",
        "on:",
        "  push:",
        '    tags: ["v*"]',
        "jobs:",
        "  call-publish:",
        "    uses: ./.github/workflows/reusable-publish.yml",
        "",
      ].join("\n"),
    );
    expect(getSLSALevel(dir)).toBeLessThan(3);
  });
});
