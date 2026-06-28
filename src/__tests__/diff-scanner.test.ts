import { describe, it, expect } from "vitest";
import { getChangedFiles } from "../diff-scanner.js";

describe("diff-scanner injection hardening", () => {
  it("rejects a sinceCommit with shell metacharacters and does not run git", () => {
    // A crafted ref must never reach git; the guard returns an empty list
    // instead of executing anything.
    expect(getChangedFiles("/tmp", "main; echo pwned")).toEqual([]);
    expect(getChangedFiles("/tmp", "$(touch /tmp/scg-pwned)")).toEqual([]);
    expect(getChangedFiles("/tmp", "`id`")).toEqual([]);
    expect(getChangedFiles("/tmp", "a && rm -rf ~")).toEqual([]);
  });

  it("rejects a sinceCommit that looks like a git option", () => {
    expect(getChangedFiles("/tmp", "--output=/tmp/evil")).toEqual([]);
  });
});
