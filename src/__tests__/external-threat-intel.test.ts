/**
 * Tests for external threat intelligence feeds and caching.
 *
 * Verifies strict ecosystem prefixing, fail-open resilience under network
 * timeouts/errors, cache persistence and TTL, and vulnerability enrichment
 * across OSV, FIRST EPSS, CISA KEV, and OpenSSF Scorecards.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  isValidEcosystemPrefix,
  normalizeEcosystemPrefix,
  formatPackageCacheKey,
  parsePrefixedPackage,
  ThreatIntelCache,
  queryOsv,
  queryEpss,
  queryCisaKev,
  queryScorecard,
  extractCvssFromOsv,
  enrichVulnerabilityInputs,
  gatherExternalIntel,
  SCORECARD_FALLBACK_SCORE,
  EPSS_FALLBACK_SCORE,
  LOOKUP_FAILURE_TTL_MS,
} from "../external-threat-intel.js";

function validCisaCatalog(vulnerabilities: Array<Record<string, unknown>>) {
  return {
    title: "CISA Known Exploited Vulnerabilities Catalog",
    catalogVersion: "2026.09.12",
    dateReleased: "2026-09-12T00:00:00.000Z",
    count: vulnerabilities.length,
    vulnerabilities,
  };
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-threat-intel-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("external threat intelligence", () => {
  describe("ecosystem prefixing", () => {
    it("recognizes standard ecosystem prefixes", () => {
      expect(isValidEcosystemPrefix("npm:")).toBe(true);
      expect(isValidEcosystemPrefix("pypi:")).toBe(true);
      expect(isValidEcosystemPrefix("cargo:")).toBe(true);
      expect(isValidEcosystemPrefix("golang:")).toBe(true);
      expect(isValidEcosystemPrefix("go:")).toBe(true);
      expect(isValidEcosystemPrefix("rubygems:")).toBe(true);
      expect(isValidEcosystemPrefix("ruby:")).toBe(true);
      expect(isValidEcosystemPrefix("composer:")).toBe(true);
      expect(isValidEcosystemPrefix("nuget:")).toBe(true);

      // Trailing colon optional in validation check
      expect(isValidEcosystemPrefix("npm")).toBe(true);
      expect(isValidEcosystemPrefix("PyPI")).toBe(true);

      // Unrecognized ecosystems
      expect(isValidEcosystemPrefix("unknown:")).toBe(false);
      // OSV serves Maven, Swift, Hex, CRAN, Pub and ConanCenter too. Rejecting them
      // made queryOsv throw out of a lookup whose contract is to fail open.
      expect(isValidEcosystemPrefix("maven:")).toBe(true);
      expect(isValidEcosystemPrefix("swift:")).toBe(true);
    });

    it("normalizes ecosystem prefix aliases", () => {
      // Canonical spellings are the ones this repo's feed uses: `go:` and `ruby:`.
      expect(normalizeEcosystemPrefix("golang:")).toBe("go:");
      expect(normalizeEcosystemPrefix("rubygems:")).toBe("ruby:");
      expect(normalizeEcosystemPrefix("go:")).toBe("go:");
      expect(normalizeEcosystemPrefix("ruby:")).toBe("ruby:");
      expect(normalizeEcosystemPrefix("NPM:")).toBe("npm:");
      expect(normalizeEcosystemPrefix("pypi")).toBe("pypi:");
    });

    it("throws on invalid ecosystem prefix", () => {
      expect(() => normalizeEcosystemPrefix("docker:")).toThrow(/Invalid ecosystem prefix/);
      expect(() => normalizeEcosystemPrefix("")).toThrow(/Invalid ecosystem prefix/);
    });

    it("formats standard cache keys with ecosystem prefix", () => {
      const key1 = formatPackageCacheKey("npm:", "lodash", "4.17.21");
      expect(key1).toBe("npm:lodash@4.17.21");

      const key2 = formatPackageCacheKey("pypi:", "Requests");
      expect(key2).toBe("pypi:requests@*");

      const key3 = formatPackageCacheKey("go:", "github.com/gin-gonic/gin", "1.9.0");
      expect(key3).toBe("go:github.com/gin-gonic/gin@1.9.0");

      expect(formatPackageCacheKey("maven:", "Org.Example/Library", "1.0.0"))
        .toBe("maven:Org.Example/Library@1.0.0");
      expect(formatPackageCacheKey("maven:", "org.example/library", "1.0.0"))
        .not.toBe(formatPackageCacheKey("maven:", "Org.Example/Library", "1.0.0"));
    });

    it("parses prefixed package identifiers", () => {
      const pkg1 = parsePrefixedPackage("npm:express@4.18.2");
      expect(pkg1.ecosystemPrefix).toBe("npm:");
      expect(pkg1.packageName).toBe("express");
      expect(pkg1.version).toBe("4.18.2");

      const pkg2 = parsePrefixedPackage("npm:@types/node@20.0.0");
      expect(pkg2.ecosystemPrefix).toBe("npm:");
      expect(pkg2.packageName).toBe("@types/node");
      expect(pkg2.version).toBe("20.0.0");

      const pkg3 = parsePrefixedPackage("pypi:flask");
      expect(pkg3.ecosystemPrefix).toBe("pypi:");
      expect(pkg3.packageName).toBe("flask");
      expect(pkg3.version).toBeUndefined();
    });

    it("throws when parsing package without standard prefix", () => {
      expect(() => parsePrefixedPackage("express@4.18.2")).toThrow(/Missing standard ecosystem prefix/);
      expect(() => parsePrefixedPackage("unsupported:pkg@1.0.0")).toThrow(/Invalid ecosystem prefix/);
    });
  });

  describe("ThreatIntelCache", () => {
    it("stores and retrieves values in memory", () => {
      const cache = new ThreatIntelCache();
      cache.set("test-key", { score: 42 });
      expect(cache.get("test-key")).toEqual({ score: 42 });
      expect(cache.get("non-existent")).toBeUndefined();
    });

    it("expires items when TTL is exceeded", () => {
      const cache = new ThreatIntelCache();
      // Set with 0ms TTL so it expires immediately
      cache.set("expired-key", { score: 99 }, -1);
      expect(cache.get("expired-key")).toBeUndefined();
    });

    it("persists to file and reloads", () => {
      const cache1 = new ThreatIntelCache(tmpDir);
      cache1.set("npm:pkg@1.0.0", { status: "cached" });
      cache1.flush();

      const cacheFile = path.join(tmpDir, "external-threat-cache.json");
      expect(fs.existsSync(cacheFile)).toBe(true);

      const cache2 = new ThreatIntelCache(tmpDir);
      expect(cache2.get("npm:pkg@1.0.0")).toEqual({ status: "cached" });
    });

    it("clears cache entries and removes file", () => {
      const cache = new ThreatIntelCache(tmpDir);
      cache.set("npm:test@1.0.0", { valid: true });
      cache.flush();

      const cacheFile = path.join(tmpDir, "external-threat-cache.json");
      expect(fs.existsSync(cacheFile)).toBe(true);

      cache.clear();
      expect(cache.get("npm:test@1.0.0")).toBeUndefined();
      expect(fs.existsSync(cacheFile)).toBe(false);
    });
  });

  describe("OSV Client with fail-open resilience", () => {
    it("identifies OSV Malicious Database records", async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            vulns: [
              {
                id: "MAL-2024-001",
                summary: "Malicious backdoor in package",
                details: "Exfiltrates tokens on installation",
                aliases: ["GHSA-xxxx"],
              },
            ],
          }),
        } as unknown as Response;
      };

      const cache = new ThreatIntelCache();
      const res = await queryOsv("npm:malicious-pkg", "1.0.0", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.hasMalwareSignature).toBe(true);
      expect(res.vulns).toHaveLength(1);
      expect(res.vulns[0].id).toBe("MAL-2024-001");
      expect(res.vulns[0].isMalicious).toBe(true);
      expect(res.malwareReasons).toBeDefined();
    });

    it("handles clean packages without malware", async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            vulns: [
              {
                id: "GHSA-1234",
                summary: "Regular vulnerability: Denial of Service",
                severity: [{ type: "CVSS_V3", score: "5.3" }],
              },
            ],
          }),
        } as unknown as Response;
      };

      const cache = new ThreatIntelCache();
      const res = await queryOsv("npm:clean-pkg", "1.0.0", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.hasMalwareSignature).toBe(false);
      expect(res.vulns).toHaveLength(1);
      expect(res.vulns[0].isMalicious).toBe(false);
    });

    it("fails open on network error / timeout", async () => {
      const mockFetch = async () => {
        throw new Error("Network offline or timeout");
      };

      const cache = new ThreatIntelCache();
      const res = await queryOsv("npm:test-pkg", "1.0.0", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.hasMalwareSignature).toBe(false);
      expect(res.vulns).toHaveLength(0);
    });
  });

  describe("FIRST EPSS Client with fail-open resilience", () => {
    it("returns EPSS score for known CVE", async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            data: [
              {
                cve: "CVE-2021-44228",
                epss: "0.9754",
                percentile: "0.9998",
              },
            ],
          }),
        } as unknown as Response;
      };

      const cache = new ThreatIntelCache();
      const res = await queryEpss("CVE-2021-44228", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.cve).toBe("CVE-2021-44228");
      expect(res.epss).toBe(0.9754);
      expect(res.percentile).toBe(0.9998);
    });

    it("fails open to fallback EPSS 0.0 on error", async () => {
      const mockFetch = async () => {
        throw new Error("Connection timed out");
      };

      const cache = new ThreatIntelCache();
      const res = await queryEpss("CVE-2026-9999", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.cve).toBe("CVE-2026-9999");
      expect(res.epss).toBe(EPSS_FALLBACK_SCORE);
      expect(res.percentile).toBe(0.0);
    });
  });

  describe("CISA KEV Client with fail-open resilience", () => {
    it("identifies CVE present in catalog", async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => validCisaCatalog([
              {
                cveID: "CVE-2023-38606",
                dateAdded: "2023-07-24",
                dueDate: "2023-08-14",
                notes: "Active exploitation observed",
              },
            ]),
        } as unknown as Response;
      };

      const cache = new ThreatIntelCache();
      const res = await queryCisaKev("CVE-2023-38606", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.cve).toBe("CVE-2023-38606");
      expect(res.inKev).toBe(true);
      expect(res.dateAdded).toBe("2023-07-24");
    });

    it("reports inKev false for non-catalog CVE", async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => validCisaCatalog([
              {
                cveID: "CVE-2023-38606",
              },
            ]),
        } as unknown as Response;
      };

      const cache = new ThreatIntelCache();
      const res = await queryCisaKev("CVE-2026-0000", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.cve).toBe("CVE-2026-0000");
      expect(res.inKev).toBe(false);
    });

    it("fails open to inKev false on network error", async () => {
      const mockFetch = async () => {
        throw new Error("HTTP 503 Service Unavailable");
      };

      const cache = new ThreatIntelCache();
      const res = await queryCisaKev("CVE-2026-0001", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.inKev).toBe(false);
    });
  });

  describe("OpenSSF Scorecard Client with fail-open resilience", () => {
    it("rejects credential-bearing repository URLs without leaking them", async () => {
      const secret = "synthetic-secret-marker";
      const fetchMock = async () => {
        throw new Error("must not fetch");
      };

      const result = await queryScorecard(`https://user:${secret}@github.com/owner/repo`, {
        cache: new ThreatIntelCache(tmpDir),
        fetchFn: fetchMock as unknown as typeof fetch,
      });

      expect(result.status).toBe("invalid");
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(fs.existsSync(path.join(tmpDir, "external-threat-cache.json"))).toBe(false);
    });

    it("does not cache a malformed successful response", async () => {
      let calls = 0;
      const cache = new ThreatIntelCache();
      const fetchMock = async () => {
        calls++;
        return {
          ok: true,
          json: async () => calls === 1 ? { date: "2026-09-12" } : { score: 8.4 },
        } as Response;
      };

      expect((await queryScorecard("owner/repo", { cache, fetchFn: fetchMock as typeof fetch })).status)
        .toBe("invalid");
      expect((await queryScorecard("owner/repo", { cache, fetchFn: fetchMock as typeof fetch })).score)
        .toBe(8.4);
      expect(calls).toBe(2);
    });

    it("retrieves Scorecard metrics for repository", async () => {
      const mockFetch = async () => {
        return {
          ok: true,
          json: async () => ({
            score: 7.8,
            date: "2026-09-01",
            checks: [
              { name: "Binary-Artifacts", score: 10 },
              { name: "Branch-Protection", score: 8 },
            ],
          }),
        } as unknown as Response;
      };

      const cache = new ThreatIntelCache();
      const res = await queryScorecard("https://github.com/example-org/sample-repo.git", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.repo).toBe("example-org/sample-repo");
      expect(res.score).toBe(7.8);
      expect(res.checks).toBeDefined();
      expect(res.checks?.["Branch-Protection"]).toBe(8);
    });

    it("treats an unindexed repository as not found rather than unavailable", async () => {
      const cache = new ThreatIntelCache();
      const fetchMock = (async () => new Response(null, { status: 404 })) as typeof fetch;

      const first = await queryScorecard("owner/unindexed", { cache, fetchFn: fetchMock });
      const second = await queryScorecard("owner/unindexed", {
        cache,
        fetchFn: (async () => {
          throw new Error("the not-found result should be cached");
        }) as typeof fetch,
      });

      expect(first.status).toBe("not-found");
      expect(second.status).toBe("not-found");
      expect(second.score).toBe(SCORECARD_FALLBACK_SCORE);
    });

    it("fails open to fallback score 3.0 on error", async () => {
      const mockFetch = async () => {
        throw new Error("Timeout");
      };

      const cache = new ThreatIntelCache();
      const res = await queryScorecard("owner/repo", {
        cache,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      expect(res.repo).toBe("owner/repo");
      expect(res.score).toBe(SCORECARD_FALLBACK_SCORE);
    });
  });

  describe("CVSS extraction and enrichVulnerabilityInputs", () => {
    it("extracts CVSS score from OSV record", () => {
      const score1 = extractCvssFromOsv({
        id: "TEST-1",
        severity: [{ type: "CVSS_V3", score: "8.5" }],
      });
      expect(score1).toBe(8.5);

      const score2 = extractCvssFromOsv({
        id: "TEST-2",
        databaseSpecific: { severity: "critical" },
      });
      expect(score2).toBeUndefined();

      const scoreVector = extractCvssFromOsv({
        id: "TEST-VECTOR",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      });
      expect(scoreVector).toBe(9.8);

      const scoreAfterUnsupportedVector = extractCvssFromOsv({
        id: "TEST-MIXED-VECTORS",
        severity: [
          { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
          { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
        ],
      });
      expect(scoreAfterUnsupportedVector).toBe(9.8);

      const changedScopeV31 = extractCvssFromOsv({
        id: "TEST-V31-CHANGED-SCOPE",
        severity: [{
          type: "CVSS_V3",
          score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        }],
      });
      expect(changedScopeV31).toBe(9.7);

      // A record that states no severity has no CVSS. Substituting a "moderate" 5.0
      // manufactured up to 50 points of S_vuln for a CVE with no published vector.
      const score3 = extractCvssFromOsv({ id: "TEST-3" });
      expect(score3).toBeUndefined();
    });

    it("enriches vulnerability inputs with EPSS and CISA KEV", async () => {
      const mockFetch = async (url: string) => {
        if (url.includes("epss")) {
          return {
            ok: true,
            json: async () => ({
              data: [{ cve: "CVE-2024-1111", epss: "0.45", percentile: "0.80" }],
            }),
          } as unknown as Response;
        }
        if (url.includes("cisa.gov")) {
          return {
            ok: true,
            json: async () => validCisaCatalog([{ cveID: "CVE-2024-1111" }]),
          } as unknown as Response;
        }
        return { ok: false } as unknown as Response;
      };

      const cache = new ThreatIntelCache();
      const enriched = await enrichVulnerabilityInputs(
        [{ id: "CVE-2024-1111", cvss: 7.2 }],
        { cache, fetchFn: mockFetch as unknown as typeof fetch },
      );

      expect(enriched).toHaveLength(1);
      expect(enriched[0].cve).toBe("CVE-2024-1111");
      expect(enriched[0].cvss).toBe(7.2);
      expect(enriched[0].epss).toBe(0.45);
      expect(enriched[0].inCisaKev).toBe(true);
    });
  });

  describe("lookup correctness", () => {
    it("rejects an EPSS response for a different CVE without caching it", async () => {
      let calls = 0;
      const cache = new ThreatIntelCache();
      const fetchMock = async () => {
        calls++;
        return {
          ok: true,
          json: async () => ({ data: [{
            cve: calls === 1 ? "CVE-1999-0001" : "CVE-2026-1234",
            epss: "0.7",
            percentile: "0.9",
          }] }),
        } as Response;
      };

      expect((await queryEpss("CVE-2026-1234", { cache, fetchFn: fetchMock as typeof fetch })).status)
        .toBe("invalid");
      expect((await queryEpss("CVE-2026-1234", { cache, fetchFn: fetchMock as typeof fetch })).epss)
        .toBe(0.7);
      expect(calls).toBe(2);
    });

    it("rejects an invalid CISA document without caching an empty catalog", async () => {
      let calls = 0;
      const cache = new ThreatIntelCache();
      const fetchMock = async () => {
        calls++;
        return {
          ok: true,
          json: async () => calls === 1
            ? {}
            : validCisaCatalog([{ cveID: "CVE-2026-1234" }]),
        } as Response;
      };

      expect((await queryCisaKev("CVE-2026-1234", { cache, fetchFn: fetchMock as typeof fetch })).status)
        .toBe("invalid");
      expect((await queryCisaKev("CVE-2026-1234", { cache, fetchFn: fetchMock as typeof fetch })).inKev)
        .toBe(true);
      expect(calls).toBe(2);
    });

    it("rejects future-dated persistent cache entries", async () => {
      fs.writeFileSync(
        path.join(tmpDir, "external-threat-cache.json"),
        JSON.stringify({
          version: 1,
          entries: {
            "epss:CVE-2026-1234": {
              data: { cve: "CVE-2026-1234", epss: 0, percentile: 0, status: "not-found" },
              cachedAt: Date.now() + 60_000,
              ttlMs: 86_400_000,
            },
          },
        }),
      );
      let fetched = false;
      const fetchMock = async () => {
        fetched = true;
        return {
          ok: true,
          json: async () => ({ data: [{ cve: "CVE-2026-1234", epss: "0.4", percentile: "0.8" }] }),
        } as Response;
      };

      const result = await queryEpss("CVE-2026-1234", {
        cache: new ThreatIntelCache(tmpDir),
        fetchFn: fetchMock as typeof fetch,
      });
      expect(fetched).toBe(true);
      expect(result.epss).toBe(0.4);
    });

    it("requests the Scorecard path with owner and repo as separate segments", async () => {
      let seen = "";
      const mockFetch = async (url: string) => {
        seen = url;
        return { ok: false, status: 404 } as unknown as Response;
      };
      await queryScorecard("owner/repo", {
        cache: new ThreatIntelCache(),
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      // encodeURIComponent(slug) encoded the "/" and every lookup 404'd into the
      // 3.0 fallback, which then always produced S_hyg = 70.
      expect(seen).toBe("https://api.securityscorecards.dev/projects/github.com/owner/repo");
      expect(seen).not.toContain("%2F");
    });

    it("stores a timeout fallback under the short failure TTL, not the 24h one", async () => {
      // Read the TTL back off the flushed cache file rather than waiting it out. A
      // fallback written with DEFAULT_TTL_MS turned one 2500ms blip into 24 hours
      // during which a real MAL- record was never requested again.
      const cache = new ThreatIntelCache(tmpDir);
      const failing = (async () => {
        throw new Error("timeout");
      }) as unknown as typeof fetch;

      await queryOsv("npm:evil-pkg", "1.0.0", { cache, fetchFn: failing });
      await queryEpss("CVE-2024-9999", { cache, fetchFn: failing });
      await queryCisaKev("CVE-2024-9999", { cache, fetchFn: failing });
      await queryScorecard("owner/repo", { cache, fetchFn: failing });
      cache.flush();

      const cacheFile = path.join(tmpDir, "external-threat-cache.json");
      const stored = (JSON.parse(fs.readFileSync(cacheFile, "utf-8")) as {
        entries: Record<string, { ttlMs: number }>;
      }).entries;

      const osvKey = `osv:${formatPackageCacheKey("npm:", "evil-pkg", "1.0.0")}`;
      expect(stored[osvKey].ttlMs).toBe(LOOKUP_FAILURE_TTL_MS);
      expect(stored["epss:CVE-2024-9999"].ttlMs).toBe(LOOKUP_FAILURE_TTL_MS);
      expect(stored["cisa-kev:CVE-2024-9999"].ttlMs).toBe(LOOKUP_FAILURE_TTL_MS);
      expect(stored["scorecard:github.com/owner/repo"].ttlMs).toBe(LOOKUP_FAILURE_TTL_MS);
      expect(LOOKUP_FAILURE_TTL_MS).toBeLessThan(24 * 60 * 60 * 1000);
    });

    it("keeps the full TTL for a KEV answer the catalog actually produced", async () => {
      const cache = new ThreatIntelCache(tmpDir);
      const working = (async () =>
        ({
          ok: true,
          json: async () => validCisaCatalog([{ cveID: "CVE-2024-3094" }]),
        }) as unknown as Response) as unknown as typeof fetch;

      const hit = await queryCisaKev("CVE-2024-3094", { cache, fetchFn: working });
      const miss = await queryCisaKev("CVE-2024-0001", { cache, fetchFn: working });
      cache.flush();

      expect(hit.inKev).toBe(true);
      expect(miss.inKev).toBe(false);

      const cacheFile = path.join(tmpDir, "external-threat-cache.json");
      const stored = (JSON.parse(fs.readFileSync(cacheFile, "utf-8")) as {
        entries: Record<string, { ttlMs: number }>;
      }).entries;
      // A negative reached WITH the catalog is an answer and keeps the long TTL.
      expect(stored["cisa-kev:CVE-2024-0001"].ttlMs).toBeGreaterThan(LOOKUP_FAILURE_TTL_MS);
    });

    it("does not read an ordinary CVE write-up as an OSV Malicious Database hit", async () => {
      const mockFetch = (async () =>
        ({
          ok: true,
          json: async () => ({
            vulns: [
              {
                id: "CVE-2021-1234",
                summary:
                  "Improper input validation lets an attacker install a backdoor via a crafted payload",
              },
            ],
          }),
        }) as unknown as Response) as unknown as typeof fetch;

      const res = await queryOsv("npm:express", "4.0.0", {
        cache: new ThreatIntelCache(),
        fetchFn: mockFetch,
      });

      expect(res.vulns).toHaveLength(1);
      expect(res.hasMalwareSignature).toBe(false);
      expect(res.vulns[0].isMalicious).toBe(false);
    });

    it("marks a MAL- record malicious", async () => {
      const mockFetch = (async () =>
        ({
          ok: true,
          json: async () => ({ vulns: [{ id: "MAL-2024-0001", summary: "" }] }),
        }) as unknown as Response) as unknown as typeof fetch;

      const res = await queryOsv("npm:evil", "1.0.0", {
        cache: new ThreatIntelCache(),
        fetchFn: mockFetch,
      });
      expect(res.hasMalwareSignature).toBe(true);
    });

    it("fails open instead of throwing on an unparseable package identifier", async () => {
      const res = await queryOsv("express", undefined, { cache: new ThreatIntelCache() });
      expect(res).toEqual({ vulns: [], hasMalwareSignature: false, status: "invalid" });
    });

    it("rejects a chunked response that exceeds the body limit", async () => {
      const oversized = JSON.stringify({ vulns: [], padding: "x".repeat(6 * 1024 * 1024) });
      const fetchMock = (async () => new Response(oversized, {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch;

      const result = await queryOsv("npm:bounded-body", "1.0.0", {
        cache: new ThreatIntelCache(),
        fetchFn: fetchMock,
      });
      expect(result.status).toBe("invalid");
    });

    it("never writes an oversized persistent cache file", () => {
      const cache = new ThreatIntelCache(tmpDir);
      cache.set("oversized-entry", { payload: "x".repeat(6 * 1024 * 1024) });
      cache.flush();

      const cacheFile = path.join(tmpDir, "external-threat-cache.json");
      expect(fs.statSync(cacheFile).size).toBeLessThanOrEqual(5 * 1024 * 1024);
      expect(fs.readFileSync(cacheFile, "utf-8")).not.toContain("oversized-entry");
    });
  });

  describe("npm inventory orchestration", () => {
    const osvFetch = (seenNames: string[], maliciousName?: string) =>
      (async (url: string | URL | Request, init?: RequestInit) => {
        expect(String(url)).toBe("https://api.osv.dev/v1/query");
        const body = JSON.parse(String(init?.body)) as { package: { name: string } };
        seenNames.push(body.package.name);
        return {
          ok: true,
          json: async () => ({
            vulns: body.package.name === maliciousName
              ? [{ id: "MAL-2026-DUPLICATE", summary: "confirmed test record" }]
              : [],
          }),
        } as Response;
      }) as typeof fetch;

    it.each([
      "github:example-org/example-repo",
      "git+ssh://git@github.com/example-org/example-repo.git",
    ])("resolves the package repository form %s for Scorecard", async (repository) => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
        name: "root",
        version: "1.0.0",
        repository,
      }));
      const requested: string[] = [];

      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: (async (input: string | URL | Request) => {
          const url = String(input);
          requested.push(url);
          if (url.includes("api.securityscorecards.dev")) {
            return { ok: true, status: 200, json: async () => ({ score: 8.2 }) } as Response;
          }
          return { ok: true, status: 200, json: async () => ({ vulns: [] }) } as Response;
        }) as typeof fetch,
      });

      expect(requested).toContain(
        "https://api.securityscorecards.dev/projects/github.com/example-org/example-repo",
      );
      expect(result.statuses.scorecard).toBe("ok");
      expect(result.partial).toBe(false);
    });

    it("does not accept credentials while normalizing Git SSH repository URLs", async () => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
        name: "root",
        version: "1.0.0",
        repository: "git+ssh://attacker:synthetic-secret@github.com/example-org/example-repo.git",
      }));
      const requested: string[] = [];

      await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: (async (input: string | URL | Request) => {
          requested.push(String(input));
          return { ok: true, status: 200, json: async () => ({ vulns: [] }) } as Response;
        }) as typeof fetch,
      });

      expect(requested.some((url) => url.includes("api.securityscorecards.dev"))).toBe(false);
      expect(requested.join(" ")).not.toContain("synthetic-secret");
    });

    it("retains every installed bom-ref for one queried package version", async () => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({ name: "root", version: "1.0.0" }));
      fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "root", version: "1.0.0" },
          "node_modules/dup": { name: "dup", version: "2.0.0" },
          "node_modules/parent/node_modules/dup": { name: "dup", version: "2.0.0" },
        },
      }));
      const seen: string[] = [];

      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: osvFetch(seen, "dup"),
      });

      expect(seen.filter((name) => name === "dup")).toHaveLength(1);
      expect(result.confirmedMalware.map((match) => match.affectsRef)).toEqual([
        "node_modules/dup",
        "node_modules/parent/node_modules/dup",
      ]);
      expect(result.vulnerabilities.map((match) => match.affectsRef)).toEqual([
        "node_modules/dup",
        "node_modules/parent/node_modules/dup",
      ]);
    });

    it("falls back to exact package.json dependencies when a v1 lock has no inventory", async () => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
        name: "root",
        version: "1.0.0",
        dependencies: { "fallback-dep": "3.2.1" },
      }));
      fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify({
        lockfileVersion: 1,
        dependencies: { "legacy-only": { version: "9.9.9" } },
      }));
      const seen: string[] = [];

      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: osvFetch(seen, "fallback-dep"),
      });

      expect(seen).toContain("root");
      expect(seen).toContain("fallback-dep");
      expect(seen).not.toContain("legacy-only");
      expect(result.packagesQueried).toBe(2);
      expect(result.partial).toBe(true);
      expect(result.notes).toContain(
        "package-lock.json has no supported v2+ package inventory; using direct dependencies only",
      );
      expect(result.confirmedMalware[0]?.affectsRef).toBe("fallback-dep");
    });

    it("marks an unreadable existing lockfile as partial coverage", async () => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
        name: "root",
        version: "1.0.0",
        dependencies: { direct: "1.2.3" },
      }));
      fs.writeFileSync(path.join(tmpDir, "package-lock.json"), "{not-json");
      const seen: string[] = [];

      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: osvFetch(seen),
      });

      expect(seen).toEqual(["root", "direct"]);
      expect(result.partial).toBe(true);
      expect(result.notes).toContain(
        "package-lock.json could not be safely read; using direct dependencies only",
      );
    });

    it("queries the resolved package behind an exact npm alias", async () => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
        name: "root",
        version: "1.0.0",
        dependencies: { alias: "npm:@scope/real-package@4.5.6" },
      }));
      const seen: string[] = [];

      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: osvFetch(seen, "@scope/real-package"),
      });

      expect(seen).toEqual(["root", "@scope/real-package"]);
      expect(result.confirmedMalware[0]?.packageName).toBe("@scope/real-package");
      expect(result.confirmedMalware[0]?.affectsRef).toBe("alias");
    });

    it("ignores malformed aliases before selecting a valid CVE for enrichment", async () => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
        name: "root",
        version: "1.0.0",
      }));
      const fetchMock = (async (url: string | URL | Request) => {
        const text = String(url);
        if (text.includes("api.osv.dev")) {
          return {
            ok: true,
            json: async () => ({
              vulns: [{
                id: "GHSA-valid-alias",
                aliases: ["CVE-not-valid", "CVE-2026-12345"],
                severity: [{ type: "CVSS_V3", score: "9.8" }],
              }],
            }),
          } as Response;
        }
        if (text.includes("api.first.org")) {
          return {
            ok: true,
            json: async () => ({
              data: [{ cve: "CVE-2026-12345", epss: "0.9", percentile: "0.99" }],
            }),
          } as Response;
        }
        if (text.includes("cisa.gov")) {
          return {
            ok: true,
            json: async () => validCisaCatalog([{ cveID: "CVE-2026-12345" }]),
          } as Response;
        }
        return { ok: false } as Response;
      }) as typeof fetch;

      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: fetchMock,
      });

      expect(result.vulnerabilities[0]?.cve).toBe("CVE-2026-12345");
      expect(result.vulnerabilities[0]?.epss).toBe(0.9);
      expect(result.vulnerabilities[0]?.inCisaKev).toBe(true);
    });

    it("does not mark a resolved npm workspace link stub as skipped coverage", async () => {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({ name: "root", version: "1.0.0" }));
      fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "root", version: "1.0.0" },
          "node_modules/local-module": { link: true, resolved: "packages/local-module" },
          "packages/local-module": { name: "local-module", version: "1.2.3" },
        },
      }));
      const seen: string[] = [];

      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        fetchFn: osvFetch(seen),
      });

      expect(seen).toEqual(["root", "local-module"]);
      expect(result.packagesSkipped).toBe(0);
      expect(result.partial).toBe(false);
    });

    it("stops scheduling package lookups after the global advisory budget is full", async () => {
      const packages: Record<string, { name: string; version: string }> = {
        "": { name: "root", version: "1.0.0" },
      };
      for (let index = 0; index < 24; index++) {
        packages[`node_modules/pkg-${index}`] = { name: `pkg-${index}`, version: "1.0.0" };
      }
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify(packages[""]));
      fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify({
        lockfileVersion: 3,
        packages,
      }));

      let calls = 0;
      const vulnerabilities = Array.from({ length: 1_000 }, (_, index) => ({
        id: `GHSA-BUDGET-${index}`,
      }));
      const result = await gatherExternalIntel(tmpDir, {
        cache: new ThreatIntelCache(),
        maxPackages: 25,
        fetchFn: (async () => {
          calls++;
          return {
            ok: true,
            json: async () => ({ vulns: vulnerabilities }),
          } as Response;
        }) as typeof fetch,
      });

      expect(calls).toBeLessThanOrEqual(8);
      expect(result.vulnerabilities).toHaveLength(1_000);
      expect(result.packagesQueried).toBeLessThanOrEqual(8);
      expect(result.packagesSkipped).toBeGreaterThan(0);
      expect(result.partial).toBe(true);
      expect(result.notes).toContain("external advisory matches truncated at 1000");
    });
  });
});
