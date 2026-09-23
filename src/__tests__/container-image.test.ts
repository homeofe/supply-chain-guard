import { describe, it, expect } from "vitest";
import {
  extractImageReferences,
  isImageReferenceFile,
  parseImageReference,
  scanImageReferences,
} from "../container-image.js";
import type { FeedIOC } from "../threat-intel.js";

const DIGEST = "a".repeat(64);
const CLEAN_DIGEST = "b".repeat(64);
const FEED: FeedIOC[] = [
  { type: "package", value: "docker:evilns/tool@6.6.6", severity: "critical", confidence: 1.0, family: "TestFamily" },
  { type: "package", value: `docker:evilns/tool@sha256:${DIGEST}`, severity: "critical", confidence: 1.0 },
  { type: "package", value: "docker:library/badbase@1.0", severity: "high", confidence: 0.9 },
];

const hits = (content: string, file: string, feed: FeedIOC[] = FEED) =>
  scanImageReferences(content, file, feed).filter((f) => f.rule === "DOCKER_MALICIOUS_IMAGE");

describe("parseImageReference", () => {
  it("normalises Docker Hub names and keeps other registries distinct", () => {
    expect(parseImageReference("evilns/tool:6.6.6")).toEqual({ name: "evilns/tool", tag: "6.6.6", digest: undefined });
    expect(parseImageReference("docker.io/EvilNS/Tool:6.6.6")?.name).toBe("evilns/tool");
    expect(parseImageReference("index.docker.io/evilns/tool")?.name).toBe("evilns/tool");
    expect(parseImageReference("badbase:1.0")?.name).toBe("library/badbase");
    expect(parseImageReference("ghcr.io/evilns/tool:6.6.6")?.name).toBe("ghcr.io/evilns/tool");
    expect(parseImageReference("localhost:5000/evilns/tool:6.6.6")).toEqual({
      name: "localhost:5000/evilns/tool", tag: "6.6.6", digest: undefined,
    });
  });

  it("separates tag and digest", () => {
    expect(parseImageReference(`evilns/tool:6.6.6@sha256:${DIGEST}`)).toEqual({
      name: "evilns/tool", tag: "6.6.6", digest: `sha256:${DIGEST}`,
    });
    expect(parseImageReference(`evilns/tool@sha256:${DIGEST}`)?.tag).toBeUndefined();
  });

  it("rejects variables, empty and malformed references", () => {
    for (const bad of ["${BASE_IMAGE}", "$BASE", "", "evilns/tool@sha256:short", "UPPER CASE", "scratch"]) {
      expect(parseImageReference(bad), bad).toBeNull();
    }
  });
});

describe("isImageReferenceFile", () => {
  it("accepts Dockerfiles, Containerfiles and YAML", () => {
    for (const f of ["Dockerfile", "app/Dockerfile.prod", "Containerfile", "docker-compose.yml", "k8s/deploy.yaml"]) {
      expect(isImageReferenceFile(f), f).toBe(true);
    }
    expect(isImageReferenceFile("package.json")).toBe(false);
  });
});

describe("extractImageReferences", () => {
  it("reads FROM (with --platform and AS) and COPY --from, skipping stage names", () => {
    const dockerfile = [
      "ARG BASE=node:22",
      "FROM --platform=$BUILDPLATFORM evilns/tool:6.6.6 AS build",
      "FROM ${BASE}",
      "FROM build AS final",
      "COPY --from=build /out /out",
      `COPY --from=evilns/tool@sha256:${DIGEST} /bin/x /x`,
      "# FROM evilns/commented:1",
      "FROM scratch",
    ].join("\n");
    expect(extractImageReferences(dockerfile, "Dockerfile").map((r) => r.raw)).toEqual([
      "evilns/tool:6.6.6",
      `evilns/tool@sha256:${DIGEST}`,
    ]);
  });

  it("reads image: values and docker:// references from YAML", () => {
    const yaml = [
      "services:",
      "  scan:",
      '    image: "evilns/tool:6.6.6"',
      "  db:",
      "    image: postgres:16 # comment",
      "jobs:",
      "  x:",
      "    steps:",
      "      - uses: docker://evilns/tool:6.6.6",
      "    container:",
      "      image: ${{ matrix.image }}",
      "  y:",
      "    container: evilns/tool:6.6.6",
    ].join("\n");
    expect(extractImageReferences(yaml, "docker-compose.yml").map((r) => `${r.raw}:${r.line}`)).toEqual([
      "evilns/tool:6.6.6:3",
      "postgres:16:5",
      "evilns/tool:6.6.6:9",
      "evilns/tool:6.6.6:13",
    ]);
  });
});

describe("scanImageReferences", () => {
  it("flags a known-bad tag and reports its line", () => {
    const found = hits("FROM evilns/tool:6.6.6\n", "Dockerfile");
    expect(found).toHaveLength(1);
    expect(found[0]?.severity).toBe("critical");
    expect(found[0]?.category).toBe("malware");
    expect(found[0]?.line).toBe(1);
    expect(found[0]?.description).toContain("TestFamily");
  });

  // A digest names content: the same manifest pushed under another name, or
  // pulled through a mirror, is the same malicious image.
  it("flags a known-bad digest under any repository name", () => {
    expect(hits(`FROM mirror.example.com/copy/of-tool@sha256:${DIGEST}\n`, "Dockerfile")).toHaveLength(1);
    expect(hits(`image: evilns/tool:clean@sha256:${DIGEST}\n`, "compose.yaml")).toHaveLength(1);
  });

  it("matches official images through the library/ namespace", () => {
    expect(hits("FROM badbase:1.0\n", "Dockerfile")).toHaveLength(1);
    expect(hits("FROM docker.io/library/badbase:1.0\n", "Dockerfile")).toHaveLength(1);
  });

  // The controls: other tags, a clean digest, and the same name on another
  // registry are different images.
  it("leaves other tags, clean digests and other registries alone", () => {
    expect(hits("FROM evilns/tool:6.6.7\n", "Dockerfile")).toEqual([]);
    expect(hits(`FROM evilns/tool@sha256:${CLEAN_DIGEST}\n`, "Dockerfile")).toEqual([]);
    expect(hits("FROM ghcr.io/evilns/tool:6.6.6\n", "Dockerfile")).toEqual([]);
    expect(hits("FROM evilns/tool\n", "Dockerfile")).toEqual([]);
  });

  it("reports each reference once per file", () => {
    expect(hits("FROM evilns/tool:6.6.6\nFROM evilns/tool:6.6.6\n", "Dockerfile")).toHaveLength(1);
  });
});
