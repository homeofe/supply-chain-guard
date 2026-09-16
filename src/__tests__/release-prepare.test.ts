import { describe, it, expect } from "vitest";

import { cutoffFor, advanceCutoff } from "../../scripts/release-prepare.mjs";

describe("cutoffFor", () => {
  it("is 30 days before the given date", () => {
    expect(cutoffFor(new Date("2026-09-16T00:00:00Z"))).toBe("2026-08-17");
  });

  // A test without a pinned `now` takes the real date and the real window. On
  // 2026-09-14 that broke feed-import.test.ts on every branch at once, and a
  // green run the day before proved nothing.
  it("does not read the clock", () => {
    const pinned = new Date("2026-09-16T00:00:00Z");
    const before = cutoffFor(pinned);

    const realNow = Date.now;
    Date.now = () => realNow() + 400 * 86_400_000;
    try {
      expect(cutoffFor(pinned)).toBe(before);
    } finally {
      Date.now = realNow;
    }
  });

  it("crosses month and year boundaries correctly", () => {
    expect(cutoffFor(new Date("2026-01-15T00:00:00Z"))).toBe("2025-12-16");
    // 2024 was a leap year, so the 29th of February is in the window.
    expect(cutoffFor(new Date("2024-03-20T00:00:00Z"))).toBe("2024-02-19");
  });

  it("honours an explicit window", () => {
    expect(cutoffFor(new Date("2026-09-16T00:00:00Z"), 0)).toBe("2026-09-16");
    expect(cutoffFor(new Date("2026-09-16T00:00:00Z"), 1)).toBe("2026-09-15");
  });

  // An invalid Date returns NaN from getTime(), and `new Date(NaN).toISOString()`
  // throws a RangeError that says nothing about where the bad value came from.
  it("refuses an invalid or absent date rather than throwing later", () => {
    expect(() => cutoffFor(new Date("not-a-date"))).toThrow(/valid Date/);
    expect(() => cutoffFor(undefined as unknown as Date)).toThrow(/valid Date/);
    expect(() => cutoffFor("2026-09-16" as unknown as Date)).toThrow(/valid Date/);
  });

  it("refuses a window that is not a non-negative integer", () => {
    const now = new Date("2026-09-16T00:00:00Z");
    expect(() => cutoffFor(now, -1)).toThrow(/non-negative integer/);
    expect(() => cutoffFor(now, 1.5)).toThrow(/non-negative integer/);
  });
});

describe("advanceCutoff", () => {
  const config = {
    bundleCutoffDate: "2026-08-17",
    maxBundledEntries: 15000,
    maxBundleBytes: 2097152,
  };

  it("moves the cutoff forward and leaves the other fields alone", () => {
    const next = advanceCutoff(config, "2026-09-16");
    expect(next.bundleCutoffDate).toBe("2026-09-16");
    expect(next.maxBundledEntries).toBe(15000);
    expect(next.maxBundleBytes).toBe(2097152);
  });

  it("does not mutate the config it was given", () => {
    advanceCutoff(config, "2026-09-16");
    expect(config.bundleCutoffDate).toBe("2026-08-17");
  });

  it("accepts an unchanged date", () => {
    expect(advanceCutoff(config, "2026-08-17").bundleCutoffDate).toBe("2026-08-17");
  });

  // Moving it backwards does not return migrated entries to the bundle. It only
  // makes the placement gate red on entries that are exactly where the policy
  // put them, with a message about a violation nobody introduced.
  it("refuses to move the cutoff backwards", () => {
    expect(() => advanceCutoff(config, "2026-07-01")).toThrow(/backwards/);
  });
});
