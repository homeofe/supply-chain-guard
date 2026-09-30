import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// The image keeps the threat-feed and catalog cache in /cache (SCG_CACHE_DIR).
// A named volume mounted on a path the image does not create starts
// root-owned and the scg user cannot write it: measured, and exactly what the
// first README example (a volume on the user's home cache path) got wrong
// with every unit test green. These cases hold the three places together; the
// "Docker build and smoke" job in ci.yml runs the documented mount for real.

const ROOT = path.resolve(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), "utf8").replace(/\r\n/g, "\n");
const code = (text: string) =>
  text
    .split("\n")
    .filter((l) => !/^\s*#/.test(l))
    .join("\n");

describe("the image's cache directory", () => {
  const dockerfile = code(read("Dockerfile"));
  const finalStage = dockerfile.slice(dockerfile.lastIndexOf("\nFROM "));

  it("is created in the final stage and owned by the user the image runs as", () => {
    const run = finalStage.match(/^RUN addgroup -S scg && adduser -S scg -G scg && (.+)$/m);
    expect(run, "the user-creation RUN line").not.toBeNull();
    expect(run![1]).toMatch(/mkdir -p [^&]*\/cache\b/);
    expect(run![1]).toMatch(/chown scg:scg [^&]*\/cache\b/);
    expect(finalStage.indexOf(run![0])).toBeLessThan(finalStage.indexOf("\nUSER scg"));
  });

  it("is what SCG_CACHE_DIR names", () => {
    expect(finalStage).toMatch(/^ENV SCG_CACHE_DIR=\/cache$/m);
  });

  it("is where the README mounts the cache volume, never a home path", () => {
    const readme = read("README.md");
    const docker = readme.split("\n").filter((l) => /^docker run /.test(l));
    const cacheMounts = docker.filter((l) => /-v scg-cache:/.test(l));
    expect(cacheMounts.length).toBeGreaterThanOrEqual(2);
    for (const l of cacheMounts) expect(l).toMatch(/-v scg-cache:\/cache /);
    for (const l of docker) expect(l, l).not.toMatch(/\/home\//);
  });

  it("is checked with a real named volume in the Docker smoke job", () => {
    const ci = code(read(".github/workflows/ci.yml"));
    const step = ci.split("- name: The documented cache volume is writable by the image user")[1] ?? "";
    expect(step, "the smoke step").not.toBe("");
    const body = step.split(/\n {6}- name: |\n {2}[a-z]/)[0];
    expect(body).toMatch(/docker run --rm -v "\$vol:\/cache"/);
    expect(body).toMatch(/touch "\$SCG_CACHE_DIR\/probe"/);
    expect(body).toMatch(/exit 1/);
  });
});
