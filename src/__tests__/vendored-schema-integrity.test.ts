/**
 * The conformance proof has to be anchored to something.
 *
 * `sbom-correctness-cluster.test.ts` validates every emitted document against
 * three vendored CycloneDX schema files. That proof is only worth what the
 * fixtures are worth: if one of them is swapped, truncated, or silently rewritten
 * to CRLF by a Windows checkout, the suite goes on reporting "valid" while
 * validating against something that is no longer the published specification.
 *
 * `.gitattributes` already asserts that this check exists. Its comment justifies
 * pinning these files to LF by saying that otherwise "every recorded checksum
 * would stop matching, so the one check that says 'this is still the official
 * schema' could no longer be run."
 *
 * Nothing ran it. The checksums were recorded in the fixtures README and never
 * compared to anything - a control described in prose, justifying a rule, with no
 * implementation behind it. This file is that implementation, so the sentence in
 * `.gitattributes` becomes true rather than aspirational.
 *
 * The README stays the single source of the expected values: this test parses
 * them out of it rather than carrying a second copy, because two copies of a
 * checksum is how one of them quietly stops matching.
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";

const FIXTURE_DIR = path.join(__dirname, "fixtures", "cyclonedx");
const README = path.join(FIXTURE_DIR, "README.md");

/** `| \`name.json\` | url | \`<64 hex>\` |` rows of the README's table. */
function recordedChecksums(): Map<string, string> {
  const text = fs.readFileSync(README, "utf-8");
  const found = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const file = /`([A-Za-z0-9._-]+\.json)`/.exec(line);
    const hash = /`([0-9a-f]{64})`/.exec(line);
    if (file && hash) found.set(file[1], hash[1]);
  }
  return found;
}

function sha256Of(file: string): string {
  return createHash("sha256").update(fs.readFileSync(path.join(FIXTURE_DIR, file))).digest("hex");
}

describe("vendored CycloneDX schemas are the files their checksums name", () => {
  const recorded = recordedChecksums();
  const present = fs
    .readdirSync(FIXTURE_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();

  it("the README records a checksum for every vendored schema, and no others", () => {
    // Guards the direction the per-file assertions cannot: adding a fourth
    // schema without recording its checksum would otherwise be invisible, and
    // this whole file would keep passing while covering less than it appears to.
    expect(present.length).toBeGreaterThan(0);
    expect([...recorded.keys()].sort()).toEqual(present);
  });

  for (const file of present) {
    it(`${file} matches its recorded SHA-256`, () => {
      const expected = recorded.get(file);
      expect(expected, `${file} has no checksum recorded in the fixtures README`).toBeDefined();
      expect(sha256Of(file)).toBe(expected);
    });
  }

  it("no schema carries a CR, so an autocrlf checkout cannot silently rewrite them", () => {
    // The failure this pins is not corruption but a line-ending rewrite: with
    // core.autocrlf=true and without the .gitattributes rule, every one of these
    // files would hash differently on a Windows checkout while looking identical
    // in every editor and diff.
    for (const file of present) {
      const bytes = fs.readFileSync(path.join(FIXTURE_DIR, file));
      expect(bytes.includes(0x0d), `${file} contains CR; the eol=lf rule is not holding`).toBe(false);
    }
  });

  it("control: the comparison can fail", () => {
    // Without this, "every checksum matched" is indistinguishable from "the
    // comparison never ran" - which is precisely the defect class this suite was
    // written to close, so it must not be reintroduced by the suite itself.
    const real = sha256Of(present[0]);
    const tampered = createHash("sha256").update(fs.readFileSync(path.join(FIXTURE_DIR, present[0])))
      .update("one extra byte").digest("hex");
    expect(tampered).not.toBe(real);
    expect(recorded.get(present[0])).not.toBe(tampered);
  });
});
