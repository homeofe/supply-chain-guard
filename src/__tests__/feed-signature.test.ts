import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { generateKeyPairSync, sign, createPublicKey } from "node:crypto";

vi.mock("node:https", () => {
  const get = vi.fn();
  return { default: { get }, get };
});

import * as https from "node:https";
import { refreshFeed, DEFAULT_FEED_URL, feedSignatureUrlFor, newestSignedReleaseFeedUrl } from "../feed.js";
import {
  FEED_SIGNING_PUBLIC_KEY_PEM,
  FEED_SIGNING_KEY_FINGERPRINT_PREFIX,
  FEED_SIGNATURE_FILE,
  FEED_SIGNED_COPY_FILE,
  feedSigningKeyFingerprint,
  setFeedPublicKeyForTests,
} from "../feed-signing-key.js";
import { FEED_CACHE_FILE, loadThreatIntel, resetThreatIntelCache } from "../threat-intel.js";
import { scan } from "../scanner.js";

const NO_FLOOR = { minEntries: 0 };
const ROOT = path.resolve(__dirname, "..", "..");
const CI = fs.readFileSync(path.join(ROOT, ".github", "workflows", "ci.yml"), "utf8");

const pair = generateKeyPairSync("ed25519");
const otherPair = generateKeyPairSync("ed25519");
const sigOf = (data: string | Buffer, key = pair.privateKey) =>
  sign(null, typeof data === "string" ? Buffer.from(data) : data, key).toString("base64");

const FEED_DOC = JSON.stringify({
  schema: 1,
  generatedAt: new Date().toISOString(),
  entries: [{ type: "domain", value: "signed-fixture.example", severity: "critical", confidence: 1 }],
});
const OTHER_DOC = JSON.stringify({
  schema: 1,
  generatedAt: new Date().toISOString(),
  entries: [{ type: "domain", value: "other-fixture.example", severity: "critical", confidence: 1 }],
});

const pathOf = (url: string) => new URL(url).pathname;
const FEED_PATH = pathOf(DEFAULT_FEED_URL);
const SIG_PATH = pathOf(feedSignatureUrlFor(DEFAULT_FEED_URL));

/** Answer each request from a path -> body map; anything else is a 404. */
const serve = (routes: Record<string, string>) => {
  (https.get as unknown as ReturnType<typeof vi.fn>).mockImplementation(
    (options: { path?: string }, callback: (res: unknown) => void) => {
      const body = routes[options.path ?? ""];
      const res = new EventEmitter() as EventEmitter & { statusCode: number; headers: Record<string, string> };
      res.statusCode = body === undefined ? 404 : 200;
      res.headers = {};
      const req = new EventEmitter();
      process.nextTick(() => {
        callback(res);
        setImmediate(() => {
          if (body !== undefined) res.emit("data", Buffer.from(body, "utf8"));
          res.emit("end");
        });
      });
      return req;
    },
  );
};

let tmpDir: string;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-feedsig-"));
  vi.clearAllMocks();
  resetThreatIntelCache();
  setFeedPublicKeyForTests(pair.publicKey.export({ type: "spki", format: "pem" }) as string);
});
afterEach(() => {
  setFeedPublicKeyForTests(undefined);
  resetThreatIntelCache();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

const cacheOf = () => JSON.parse(fs.readFileSync(path.join(tmpDir, FEED_CACHE_FILE), "utf8"));

describe("the bundled feed signing key", () => {
  it("is the key the owner generated (fingerprint pinned)", () => {
    setFeedPublicKeyForTests(undefined);
    expect(feedSigningKeyFingerprint(createPublicKey(FEED_SIGNING_PUBLIC_KEY_PEM)).startsWith("91b2c7d7d50612a3")).toBe(true);
    expect(FEED_SIGNING_KEY_FINGERPRINT_PREFIX).toBe("91b2c7d7d50612a3");
  });

  it("is documented with the same fingerprint in SECURITY.md", () => {
    expect(fs.readFileSync(path.join(ROOT, "SECURITY.md"), "utf8")).toContain("91b2c7d7d50612a3");
  });

  it("defaults the refresh source to the latest release assets", () => {
    expect(DEFAULT_FEED_URL).toBe(
      "https://github.com/homeofe/supply-chain-guard/releases/latest/download/feed.json",
    );
    expect(feedSignatureUrlFor(DEFAULT_FEED_URL)).toBe(`${DEFAULT_FEED_URL}.sig`);
  });
});

describe("refreshFeed verifies the feed signature", () => {
  it("accepts a feed whose signature verifies, and keeps the signed bytes beside the cache", async () => {
    serve({ [FEED_PATH]: FEED_DOC, [SIG_PATH]: sigOf(FEED_DOC) + "\n" });
    const result = await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR);
    expect(result.entryCount).toBe(1);
    expect(result.unsigned).toBeUndefined();
    expect(fs.readFileSync(path.join(tmpDir, FEED_SIGNED_COPY_FILE), "utf8")).toBe(FEED_DOC);
    expect(fs.existsSync(path.join(tmpDir, FEED_SIGNATURE_FILE))).toBe(true);
  });

  const seedCache = async () => {
    serve({ [FEED_PATH]: FEED_DOC, [SIG_PATH]: sigOf(FEED_DOC) });
    await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR);
    return fs.readFileSync(path.join(tmpDir, FEED_CACHE_FILE), "utf8");
  };

  const cases: Array<[string, () => Record<string, string>, RegExp]> = [
    ["a missing signature", () => ({ [FEED_PATH]: OTHER_DOC }), /latest release carries no signed feed/],
    ["a signature by another key", () => ({ [FEED_PATH]: OTHER_DOC, [SIG_PATH]: sigOf(OTHER_DOC, otherPair.privateKey) }), /does not verify/],
    ["a signature over different bytes", () => ({ [FEED_PATH]: OTHER_DOC, [SIG_PATH]: sigOf(FEED_DOC) }), /does not verify/],
    ["a truncated feed", () => ({ [FEED_PATH]: OTHER_DOC.slice(0, -20), [SIG_PATH]: sigOf(OTHER_DOC) }), /does not verify/],
    ["a malformed signature", () => ({ [FEED_PATH]: OTHER_DOC, [SIG_PATH]: "not a signature!" }), /not base64/],
    ["a signature of the wrong length", () => ({ [FEED_PATH]: OTHER_DOC, [SIG_PATH]: Buffer.alloc(10).toString("base64") }), /malformed/],
    ["an empty signature", () => ({ [FEED_PATH]: OTHER_DOC, [SIG_PATH]: "\n" }), /empty/],
  ];
  for (const [name, routes, message] of cases) {
    it(`refuses ${name} and keeps the previous cache`, async () => {
      const before = await seedCache();
      serve(routes());
      await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR)).rejects.toThrow(message);
      expect(fs.readFileSync(path.join(tmpDir, FEED_CACHE_FILE), "utf8")).toBe(before);
      expect(fs.readFileSync(path.join(tmpDir, FEED_SIGNED_COPY_FILE), "utf8")).toBe(FEED_DOC);
    });
  }

  it("verifies BEFORE parsing: an unsigned non-JSON body is refused as unsigned, not as invalid JSON", async () => {
    serve({ [FEED_PATH]: "<html>not json</html>" });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR)).rejects.toThrow(/latest release carries no signed feed/);
  });
});

// A patch on an older major can become GitHub's `latest` and carry no signed
// feed. The default source then falls back to the newest release that does;
// the fallback only chooses the release, the signature is still verified.
describe("fallback when the latest release carries no signed feed", () => {
  const V6 = "https://github.com/homeofe/supply-chain-guard/releases/download/v6.5.2/feed.json";
  const V6_PATH = pathOf(V6);
  const V6_SIG_PATH = pathOf(feedSignatureUrlFor(V6));
  const resolveTo = (url: string) => ({ resolveSignedRelease: async () => url });

  it("reads the newest signed release when latest has no feed", async () => {
    serve({ [V6_PATH]: FEED_DOC, [V6_SIG_PATH]: sigOf(FEED_DOC) });
    const result = await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, resolveTo(V6));
    expect(result.entryCount).toBe(1);
    expect(fs.readFileSync(path.join(tmpDir, FEED_SIGNED_COPY_FILE), "utf8")).toBe(FEED_DOC);
  });

  it("still verifies the fallback release's signature", async () => {
    serve({ [V6_PATH]: OTHER_DOC, [V6_SIG_PATH]: sigOf(OTHER_DOC, otherPair.privateKey) });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, resolveTo(V6))).rejects.toThrow(/does not verify/);
  });

  it("does not consult the fallback when latest carries a signed feed", async () => {
    serve({ [FEED_PATH]: FEED_DOC, [SIG_PATH]: sigOf(FEED_DOC) });
    const resolver = vi.fn(async () => V6);
    await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR, { resolveSignedRelease: resolver });
    expect(resolver).not.toHaveBeenCalled();
  });

  it("never falls back for a custom URL", async () => {
    const MIRROR = "https://mirror.invalid/scg/feed.json";
    serve({ [pathOf(MIRROR)]: FEED_DOC });
    const resolver = vi.fn(async () => V6);
    await expect(refreshFeed(MIRROR, tmpDir, NO_FLOOR, { resolveSignedRelease: resolver })).rejects.toThrow(
      /--allow-unsigned-feed/,
    );
    expect(resolver).not.toHaveBeenCalled();
  });

  it("picks the highest-version release that carries both assets", async () => {
    const release = (tag: string, assets: string[], extra: Record<string, unknown> = {}) =>
      ({ tag_name: tag, draft: false, prerelease: false, assets: assets.map((name) => ({ name })), ...extra });
    const both = ["feed.json", "feed.json.sig"];
    const list = [
      release("v5.28.2", both),
      release("v6.5.2", both),
      release("v6.10.0", ["feed.json"]),
      release("v6.9.0", both, { prerelease: true }),
      release("v6.8.0", both, { draft: true }),
      release("v6.6.0", both),
      release("latest-feed", both),
    ];
    const fetcher = vi.fn(async () => ({ body: Buffer.from(JSON.stringify(list)), finalUrl: "" }));
    const url = await newestSignedReleaseFeedUrl({ maxBytes: 1_000_000, timeoutMs: 1000 } as never, fetcher as never);
    expect(url).toBe("https://github.com/homeofe/supply-chain-guard/releases/download/v6.6.0/feed.json");
    expect(fetcher.mock.calls[0]![1]).toMatchObject({ headers: { "User-Agent": "supply-chain-guard" } });
  });

  it("marks only the highest release tag as latest in the release job", () => {
    expect(CI).toMatch(/sort -V \| tail -n 1/);
    expect(CI).toContain('--latest="$latest"');
  });
});

describe("a custom feed URL", () => {
  const MIRROR = "https://mirror.invalid/scg/feed.json";
  const MIRROR_PATH = pathOf(MIRROR);

  it("must be signed by the bundled key too, fetched from <url>.sig", async () => {
    serve({ [MIRROR_PATH]: FEED_DOC, [`${MIRROR_PATH}.sig`]: sigOf(FEED_DOC) });
    const result = await refreshFeed(MIRROR, tmpDir, NO_FLOOR);
    expect(result.entryCount).toBe(1);
    expect(result.unsigned).toBeUndefined();
  });

  it("is refused without a signature unless allowUnsigned is passed", async () => {
    serve({ [MIRROR_PATH]: FEED_DOC });
    await expect(refreshFeed(MIRROR, tmpDir, NO_FLOOR)).rejects.toThrow(/--allow-unsigned-feed/);
    expect(fs.existsSync(path.join(tmpDir, FEED_CACHE_FILE))).toBe(false);
  });

  it("is accepted with allowUnsigned, which is recorded in the cache and reported", async () => {
    serve({ [MIRROR_PATH]: FEED_DOC });
    const result = await refreshFeed(MIRROR, tmpDir, NO_FLOOR, { allowUnsigned: true });
    expect(result.unsigned).toBe(true);
    expect(cacheOf().unsigned).toBe(true);
    resetThreatIntelCache();
    loadThreatIntel(tmpDir);
    const entries = loadThreatIntel(tmpDir);
    expect(entries.some((e) => e.value === "signed-fixture.example")).toBe(true);
  });

  it("has no environment-variable bypass", () => {
    const source = fs.readFileSync(path.join(ROOT, "src", "feed.ts"), "utf8");
    expect(source).not.toMatch(/process\.env/);
    const key = fs.readFileSync(path.join(ROOT, "src", "feed-signing-key.ts"), "utf8");
    expect(key.match(/process\.env\.[A-Z_]+/g)).toEqual(["process.env.VITEST"]);
  });
});

describe("the cached feed is re-verified on every load", () => {
  const writeProject = () => {
    const project = fs.mkdtempSync(path.join(os.tmpdir(), "scg-feedsig-proj-"));
    fs.writeFileSync(path.join(project, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    return project;
  };
  const seed = async () => {
    serve({ [FEED_PATH]: FEED_DOC, [SIG_PATH]: sigOf(FEED_DOC) });
    await refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR);
    resetThreatIntelCache();
  };
  const rules = async () => {
    const project = writeProject();
    try {
      const report = await scan({ target: project, format: "json", cacheDir: tmpDir });
      return { ids: report.findings.map((f) => f.rule), partial: report.partialScan };
    } finally {
      fs.rmSync(project, { recursive: true, force: true });
    }
  };

  it("an untouched refreshed cache loads and the scan is not partial", async () => {
    await seed();
    const out = await rules();
    expect(out.ids).not.toContain("THREAT_FEED_CACHE_UNREADABLE");
    expect(loadThreatIntel(tmpDir).some((e) => e.value === "signed-fixture.example")).toBe(true);
  });

  it("a cache with an entry added is unreadable and the scan is partial", async () => {
    await seed();
    const cache = cacheOf();
    cache.entries.push({ type: "domain", value: "planted.example", severity: "critical", confidence: 1 });
    fs.writeFileSync(path.join(tmpDir, FEED_CACHE_FILE), JSON.stringify(cache));
    resetThreatIntelCache();
    const out = await rules();
    expect(out.ids).toContain("THREAT_FEED_CACHE_UNREADABLE");
    expect(out.partial).toBe(true);
    expect(loadThreatIntel(tmpDir).some((e) => e.value === "planted.example")).toBe(false);
  });

  it("a cache with an entry removed is unreadable", async () => {
    await seed();
    const cache = cacheOf();
    cache.entries = [];
    fs.writeFileSync(path.join(tmpDir, FEED_CACHE_FILE), JSON.stringify(cache));
    resetThreatIntelCache();
    expect((await rules()).ids).toContain("THREAT_FEED_CACHE_UNREADABLE");
  });

  it("a replaced signed copy is unreadable even when the cache is untouched", async () => {
    await seed();
    fs.writeFileSync(path.join(tmpDir, FEED_SIGNED_COPY_FILE), OTHER_DOC);
    resetThreatIntelCache();
    expect((await rules()).ids).toContain("THREAT_FEED_CACHE_UNREADABLE");
  });

  it("a deleted signature is unreadable", async () => {
    await seed();
    fs.rmSync(path.join(tmpDir, FEED_SIGNATURE_FILE));
    resetThreatIntelCache();
    expect((await rules()).ids).toContain("THREAT_FEED_CACHE_UNREADABLE");
  });

  it("a hand-written cache with no signature is unreadable", async () => {
    fs.writeFileSync(
      path.join(tmpDir, FEED_CACHE_FILE),
      JSON.stringify({
        timestamp: new Date().toISOString(),
        entries: [{ type: "domain", value: "planted.example", severity: "critical", confidence: 1 }],
      }),
    );
    expect((await rules()).ids).toContain("THREAT_FEED_CACHE_UNREADABLE");
  });
});

describe("a newer feed in an older client", () => {
  it("one entry of an unknown type makes the whole feed invalid (documented behaviour)", async () => {
    const future = JSON.stringify({
      schema: 1,
      generatedAt: new Date().toISOString(),
      entries: [
        { type: "domain", value: "ok.example", severity: "critical", confidence: 1 },
        { type: "future-type", value: "x", severity: "critical", confidence: 1 },
      ],
    });
    serve({ [FEED_PATH]: future, [SIG_PATH]: sigOf(future) });
    await expect(refreshFeed(DEFAULT_FEED_URL, tmpDir, NO_FLOOR)).rejects.toThrow(/invalid feed entry/);
  });
});

describe("scripts/sign-feed.mjs", () => {
  const script = path.join(ROOT, "scripts", "sign-feed.mjs");
  const pem = (k: { export: (o: object) => unknown }, type: "pkcs8" | "spki") =>
    k.export({ type, format: "pem" }) as string;
  const run = (env: Record<string, string>, args: string[]) =>
    spawnSync(process.execPath, [script, ...args], {
      env: { PATH: process.env.PATH ?? "", ...env },
      encoding: "utf8",
    });

  it("signs the exact bytes of feed.json and the result verifies", () => {
    const feed = path.join(tmpDir, "feed.json");
    fs.writeFileSync(feed, FEED_DOC);
    const pub = path.join(tmpDir, "pub.pem");
    fs.writeFileSync(pub, pem(pair.publicKey, "spki"));
    const r = run({ FEED_SIGNING_KEY: pem(pair.privateKey, "pkcs8") }, [feed, `${feed}.sig`, "--public-key", pub]);
    expect(r.status).toBe(0);
    const sig = fs.readFileSync(`${feed}.sig`, "utf8");
    expect(sig.trim().split("\n")).toHaveLength(1);
    expect(sig.trim()).toBe(sigOf(FEED_DOC));
    expect(r.stdout + r.stderr).not.toContain("PRIVATE KEY");
  });

  it("exits non-zero and leaves no signature when the key does not match the embedded public key", () => {
    const feed = path.join(tmpDir, "feed.json");
    fs.writeFileSync(feed, FEED_DOC);
    const r = run({ FEED_SIGNING_KEY: pem(pair.privateKey, "pkcs8") }, [feed, `${feed}.sig`]);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("does not verify");
    expect(fs.existsSync(`${feed}.sig`)).toBe(false);
  });

  it("exits non-zero without the secret, and never echoes a bad key", () => {
    const feed = path.join(tmpDir, "feed.json");
    fs.writeFileSync(feed, FEED_DOC);
    expect(run({}, [feed, `${feed}.sig`]).status).not.toBe(0);
    const r = run({ FEED_SIGNING_KEY: "-----BEGIN PRIVATE KEY-----\nSECRETMATERIAL\n-----END PRIVATE KEY-----" }, [feed, `${feed}.sig`]);
    expect(r.status).not.toBe(0);
    expect(r.stderr + r.stdout).not.toContain("SECRETMATERIAL");
  });

  it("runs without an install: imports only node: modules", () => {
    const src = fs.readFileSync(script, "utf8");
    const imports = [...src.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const specifier of imports) expect(specifier.startsWith("node:")).toBe(true);
  });

  it("finds the embedded public key in src/feed-signing-key.ts", () => {
    // Real key, no override: a key that is not the private half must be refused,
    // which only happens if the embedded PEM was located and parsed.
    expect(() =>
      execFileSync(process.execPath, [script, path.join(ROOT, "feed.json"), path.join(tmpDir, "x.sig")], {
        env: { PATH: process.env.PATH ?? "", FEED_SIGNING_KEY: pem(otherPair.privateKey, "pkcs8") },
        stdio: "pipe",
      }),
    ).toThrow();
    expect(fs.existsSync(path.join(tmpDir, "x.sig"))).toBe(false);
  });
});

describe("the release job signs the feed", () => {
  const releaseJob = (() => {
    const start = CI.indexOf("\n  release:");
    const rest = CI.slice(start + 1);
    const next = rest.search(/\n {2}[a-z][a-z0-9-]*:\n/);
    return next === -1 ? rest : rest.slice(0, next);
  })();

  it("signs before it creates the release", () => {
    const signStep = releaseJob.indexOf("node scripts/sign-feed.mjs");
    expect(signStep).toBeGreaterThan(-1);
    expect(signStep).toBeLessThan(releaseJob.indexOf("gh release create"));
  });

  it("uploads feed.json and feed.json.sig in the one create call", () => {
    const create = releaseJob.indexOf("gh release create");
    const command = releaseJob.slice(create, releaseJob.indexOf("env:", create));
    expect(command).toMatch(/\bfeed\.json\b/);
    expect(command).toContain("feed.json.sig");
  });

  it("hands the secret to the signing step only", () => {
    expect(CI.match(/secrets\.FEED_SIGNING_KEY/g)).toHaveLength(1);
    const at = releaseJob.indexOf("secrets.FEED_SIGNING_KEY");
    const stepStart = releaseJob.lastIndexOf("\n      - name:", at);
    const stepEnd = releaseJob.indexOf("\n      - name:", at);
    expect(releaseJob.slice(stepStart, stepEnd)).toContain("sign-feed.mjs");
  });
});
