/**
 * File-digest matching (T-018).
 *
 * Before this existed, KNOWN_MALICIOUS_HASHES was consumed by exactly one
 * matcher: the substring loop in checkIOCBlocklist, which tests whether the
 * digest TEXT appears inside file content. That answers "does this file quote a
 * known-bad digest", not "is this file the malware" - a payload never contains
 * its own digest. So every entry naming a dropped artefact was unreachable by
 * the thing it names, including the ChainDrop entry literally described as
 * "dropped as .vscode/tasks.json".
 *
 * A real digest has no computable preimage, so no test can build a file that
 * matches a shipped entry. Two techniques are used instead:
 *   - unit tests pass their own index to checkFileDigest;
 *   - the end-to-end tests inject one entry into KNOWN_MALICIOUS_HASHES in
 *     beforeAll, which runs before anything builds the lazily-cached index.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  checkFileDigest,
  checkIOCBlocklist,
  KNOWN_MALICIOUS_HASHES,
} from "../ioc-blocklist.js";
import { scan } from "../scanner.js";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const md5 = (b: Buffer | string) => createHash("md5").update(b).digest("hex");

// The payload used by the end-to-end tests. Its digest is injected into the
// real collection below, which is the only way to exercise the scan path.
const E2E_PAYLOAD = "dropped-persistence-payload-for-routing-test\n";
const E2E_DIGEST = sha256(E2E_PAYLOAD);
const E2E_DESC = "test-injected dropped artefact";

let tmpRoot: string;

beforeAll(() => {
  (KNOWN_MALICIOUS_HASHES as Record<string, string>)[E2E_DIGEST] = E2E_DESC;
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "scg-digest-"));
});

afterAll(() => {
  delete (KNOWN_MALICIOUS_HASHES as Record<string, string>)[E2E_DIGEST];
  if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
});

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

describe("checkFileDigest", () => {
  it("reports a file whose SHA-256 is a known malware digest", () => {
    const bytes = Buffer.from("malicious payload bytes");
    const index = new Map([[sha256(bytes), "WEL1DROPPER stage-2 payload"]]);

    const findings = checkFileDigest(bytes, "payload.bin", index);

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("IOC_KNOWN_MALWARE_FILE_DIGEST");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].file).toBe("payload.bin");
    expect(findings[0].description).toContain("WEL1DROPPER stage-2 payload");
  });

  it("does not report the same content with a single byte changed", () => {
    const bytes = Buffer.from("malicious payload bytes");
    const index = new Map([[sha256(bytes), "WEL1DROPPER stage-2 payload"]]);

    // One byte differs; a digest match must be exact or it is not a digest.
    const altered = Buffer.from("malicious payload byteS");
    expect(checkFileDigest(altered, "payload.bin", index)).toEqual([]);
  });

  it("matches MD5 entries too, since six of the shipped digests are MD5", () => {
    const bytes = Buffer.from("ClaudeCode_x64.exe stand-in");
    const index = new Map([[md5(bytes), "ClaudeCode_x64.exe Rust dropper"]]);

    const findings = checkFileDigest(bytes, "dropper.exe", index);

    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain("md5");
  });

  it("still reports a documentation file, unlike the digest-text matcher", () => {
    // checkIOCBlocklist skips .md because documentation legitimately DISCUSSES
    // indicators. A byte-for-byte digest match is not discussion.
    const bytes = Buffer.from("payload that happens to be named .md");
    const index = new Map([[sha256(bytes), "payload"]]);

    expect(checkFileDigest(bytes, "README.md", index)).toHaveLength(1);
  });

  it("hashes raw bytes, so a non-UTF-8 payload still matches", () => {
    // The scanner decodes content as UTF-8 for the text scanners. Hashing that
    // decoded string would not reproduce a binary payload's published digest,
    // which is most of what this collection describes.
    const bytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x00, 0xff, 0xfe]);
    const index = new Map([[sha256(bytes), "ELF payload"]]);

    expect(checkFileDigest(bytes, "payload", index)).toHaveLength(1);
    // The lossy path this guards against: decode to UTF-8, then re-encode.
    const lossy = Buffer.from(bytes.toString("utf-8"), "utf-8");
    expect(sha256(lossy)).not.toBe(sha256(bytes));
  });
});

describe("shipped digest index composition", () => {
  it("excludes 40-hex keys, which mix a Git object id with a file SHA-1", () => {
    // A Git object id hashes a commit object, never file bytes. The collection
    // holds one of each at length 40 and nothing distinguishes them, so neither
    // participates in file-digest matching.
    const gitSha = "558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2";
    expect(KNOWN_MALICIOUS_HASHES).toHaveProperty(gitSha);

    const bytes = Buffer.from("anything");
    const index = new Map([[gitSha, "Nx Console malicious orphan commit"]]);
    // Proves only that a 40-hex value never equals a sha256/md5 digest, which
    // is what keeps it out of the match set.
    expect(checkFileDigest(bytes, "f.js", index)).toEqual([]);
  });

  it("keeps the digest-TEXT matcher working, which is a separate signal", () => {
    // A digest quoted in a manifest or advisory is still worth reporting; this
    // change is additive, not a replacement.
    const known = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668";
    expect(KNOWN_MALICIOUS_HASHES).toHaveProperty(known);

    const findings = checkIOCBlocklist(`const h = "${known}";`, "notes.js");
    expect(findings.some((f) => f.rule === "IOC_KNOWN_MALWARE_HASH")).toBe(true);
  });
});

describe("scan routing", () => {
  it("reports a matching file through a real directory scan", async () => {
    const dir = fixture("hit", {
      "package.json": JSON.stringify({ name: "fx", version: "1.0.0" }),
      "index.js": E2E_PAYLOAD,
    });

    const result = await scan({ target: dir, format: "json" });
    const hit = result.findings.filter(
      (f) => f.rule === "IOC_KNOWN_MALWARE_FILE_DIGEST",
    );

    expect(hit).toHaveLength(1);
    expect(hit[0].description).toContain(E2E_DESC);
    expect(hit[0].file).toBe("index.js");
  });

  it("reports a payload with NO scannable extension", async () => {
    // The decisive case. Content scanners are gated on SCANNABLE_EXTENSIONS, so
    // a compiled payload never reaches them - and compiled payloads are most of
    // what the hash collection describes. The digest check therefore runs
    // before that gate, and this test fails if it is ever moved after it.
    const dir = fixture("binary", {
      "package.json": JSON.stringify({ name: "fx", version: "1.0.0" }),
      "vendor/agent.bin": E2E_PAYLOAD,
    });

    const result = await scan({ target: dir, format: "json" });
    const hit = result.findings.filter(
      (f) => f.rule === "IOC_KNOWN_MALWARE_FILE_DIGEST",
    );

    expect(hit).toHaveLength(1);
    expect(hit[0].file).toBe("vendor/agent.bin");
  });

  it("leaves an ordinary project clean", async () => {
    const dir = fixture("clean", {
      "package.json": JSON.stringify({ name: "fx", version: "1.0.0" }),
      "index.js": "export const add = (a, b) => a + b;\n",
      "README.md": "# fx\n\nA small module.\n",
      "vendor/agent.bin": "not the payload\n",
    });

    const result = await scan({ target: dir, format: "json" });
    expect(
      result.findings.filter((f) => f.rule === "IOC_KNOWN_MALWARE_FILE_DIGEST"),
    ).toEqual([]);
  });
});
