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
    // FROM ${BASE} resolves through the global ARG default (see the next test).
    expect(extractImageReferences(dockerfile, "Dockerfile").map((r) => r.raw)).toEqual([
      "evilns/tool:6.6.6",
      "node:22",
      `evilns/tool@sha256:${DIGEST}`,
    ]);
  });

  // Only global ARGs (before the first FROM) are visible to FROM, as in Docker.
  it("resolves FROM ${ARG} from global ARG defaults, and ${X:-default}", () => {
    const dockerfile = [
      "ARG BASE=evilns/tool",
      "ARG TAG=6.6.6",
      "FROM ${BASE}:${TAG} AS one",
      "FROM ${OTHER:-evilns/tool:6.6.6} AS two",
      "ARG STAGE_ONLY=evilns/tool:6.6.6",
      "FROM ${STAGE_ONLY}",
      "FROM ${UNDEFINED}",
    ].join("\n");
    expect(extractImageReferences(dockerfile, "Dockerfile").map((r) => `${r.raw}:${r.line}`)).toEqual([
      "evilns/tool:6.6.6:3",
      "evilns/tool:6.6.6:4",
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

// Real-world reference forms, checked against the BUNDLED feed entry
// docker:aquasec/trivy@0.69.4 so a routing or prefix mistake would show.
describe("scanImageReferences: map, values and BuildKit forms", () => {
  const bundled = (content: string, file: string) =>
    scanImageReferences(content, file).filter((f) => f.rule === "DOCKER_MALICIOUS_IMAGE");

  // GitLab documents running Trivy exactly like this.
  it("reads the GitLab CI image map form (name + entrypoint)", () => {
    const ci = [
      "trivy:",
      "  stage: test",
      "  image:",
      "    name: aquasec/trivy:0.69.4",
      '    entrypoint: [""]',
      "  script:",
      "    - trivy fs .",
    ].join("\n");
    const found = bundled(ci, ".gitlab-ci.yml");
    expect(found).toHaveLength(1);
    expect(found[0]?.line).toBe(4);
    expect(bundled('scan:\n  image: {name: "aquasec/trivy:0.69.4", entrypoint: [""]}\n', ".gitlab-ci.yml")).toHaveLength(1);
  });

  it("does not read a name: that is not under image:, nor a private-registry name", () => {
    expect(bundled("job:\n  name: aquasec/trivy:0.69.4\n  image: alpine:3\n", ".gitlab-ci.yml")).toEqual([]);
    expect(bundled("scan:\n  image:\n    name: registry.internal.example/aquasec/trivy:0.69.4\n", ".gitlab-ci.yml")).toEqual([]);
  });

  it("pairs Helm-values repository + tag / digest under the same image key", () => {
    const block = [
      "scanner:",
      "  image:",
      "    repository: aquasec/trivy",
      '    tag: "0.69.4"',
      "    pullPolicy: IfNotPresent",
      "  replicas: 1",
    ].join("\n");
    expect(bundled(block, "values.yaml")).toHaveLength(1);
    expect(bundled('image: {repository: aquasec/trivy, tag: "0.69.4"}\n', "values.yaml")).toHaveLength(1);
    const digest = "27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3";
    expect(bundled(`image:\n  repository: aquasec/trivy\n  digest: sha256:${digest}\n`, "values.yaml")).toHaveLength(1);
    // registry: is part of the name, so a Docker Hub registry still matches.
    expect(bundled("image:\n  registry: docker.io\n  repository: aquasec/trivy\n  tag: 0.69.4\n", "values.yaml")).toHaveLength(1);
  });

  it("does not pair repository/tag that are not both under image:", () => {
    // Not under an image key at all.
    expect(bundled('scanner:\n  repository: aquasec/trivy\n  tag: "0.69.4"\n', "values.yaml")).toEqual([]);
    // tag is a sibling of image:, not its child.
    expect(bundled('image:\n  repository: aquasec/trivy\ntag: "0.69.4"\n', "values.yaml")).toEqual([]);
    // A deeper grandchild is not the image's own tag.
    expect(bundled('image:\n  repository: aquasec/trivy\n  extra:\n    tag: "0.69.4"\n', "values.yaml")).toEqual([]);
    // A private registry makes it a different image.
    expect(bundled("image:\n  registry: registry.internal.example\n  repository: aquasec/trivy\n  tag: 0.69.4\n", "values.yaml")).toEqual([]);
    expect(bundled("image: {registry: registry.internal.example, repository: aquasec/trivy, tag: 0.69.4}\n", "values.yaml")).toEqual([]);
  });

  it("expands global ARGs in COPY --from as it does in FROM", () => {
    const dockerfile = [
      "ARG TRIVY_IMAGE=aquasec/trivy:0.69.4",
      "FROM alpine:3.20",
      "COPY --from=${TRIVY_IMAGE} /usr/local/bin/trivy /usr/local/bin/trivy",
    ].join("\n");
    const found = bundled(dockerfile, "Dockerfile");
    expect(found).toHaveLength(1);
    expect(found[0]?.line).toBe(3);
  });

  it("reads from= inside RUN --mount, skipping build-stage names", () => {
    const dockerfile = [
      "FROM alpine:3.20 AS tools",
      "FROM alpine:3.20",
      "RUN --mount=type=cache,target=/root/.cache --mount=type=bind,from=aquasec/trivy:0.69.4,source=/usr/local/bin/trivy,target=/trivy /trivy fs /",
    ].join("\n");
    const found = bundled(dockerfile, "Dockerfile");
    expect(found).toHaveLength(1);
    expect(found[0]?.line).toBe(3);
    // A stage name in from= is not an image.
    const stage = extractImageReferences(
      "FROM aquasec/trivy:0.69.4 AS trivy\nFROM alpine:3.20\nRUN --mount=type=bind,from=trivy,target=/t /t/trivy\n",
      "Dockerfile",
    ).map((r) => r.raw);
    expect(stage).toEqual(["aquasec/trivy:0.69.4", "alpine:3.20"]);
    expect(bundled("FROM alpine:3.20\nRUN --mount=type=bind,from=registry.internal.example/aquasec/trivy:0.69.4 x\n", "Dockerfile")).toEqual([]);
  });

  // GitLab CI services: a LIST of bare image strings or maps with name:.
  it("reads GitLab CI services list items, bare and map form, job-level and top-level", () => {
    const ci = [
      "services:",
      "  - evilns/tool:6.6.6",
      "test:",
      "  services:",
      "    - name: aquasec/trivy:0.69.4",
      "      alias: trivy",
      '      entrypoint: [""]',
      "      command: [\"server\"]",
      "    - alias: db",
      "      name: postgres:16",
      '    - "redis:7"',
      "    - {name: mysql:8, alias: sql}",
      "  script:",
      "    - echo ok",
    ].join("\n");
    expect(extractImageReferences(ci, ".gitlab-ci.yml").map((r) => `${r.raw}:${r.line}`)).toEqual([
      "evilns/tool:6.6.6:2",
      "aquasec/trivy:0.69.4:5",
      "postgres:16:10",
      "redis:7:11",
      "mysql:8:12",
    ]);
    expect(hits(ci, ".gitlab-ci.yml")).toHaveLength(1);
    expect(bundled(ci, ".gitlab-ci.yml")).toHaveLength(1);
    // A compact list at the key's own indentation is the same list.
    expect(extractImageReferences("job:\n  services:\n  - name: evilns/tool:6.6.6\n  - postgres:16\n  script: [x]\n", ".gitlab-ci.yml")
      .map((r) => r.raw)).toEqual(["evilns/tool:6.6.6", "postgres:16"]);
    // One-line flow list.
    expect(extractImageReferences("job:\n  services: [evilns/tool:6.6.6, redis]\n", ".gitlab-ci.yml").map((r) => r.raw))
      .toEqual(["evilns/tool:6.6.6", "redis"]);
    // A flow-map item continued on the next lines, read once; the next item too.
    const multi = "job:\n  services:\n    - {name: evilns/tool:6.6.6,\n       alias: tool}\n    - {alias: db,\n       name: postgres:16}\n    - redis:7\n";
    expect(extractImageReferences(multi, ".gitlab-ci.yml").map((r) => `${r.raw}:${r.line}`))
      .toEqual(["evilns/tool:6.6.6:3", "postgres:16:5", "redis:7:7"]);
  });

  // Every unclosed item looks ahead a bounded number of lines; unbounded, each
  // of 50k such items would rescan the rest of the file.
  it("stays linear on many unclosed flow-map service items", () => {
    const ci = ["job:", "  services:", ...Array.from({ length: 50_000 }, () => "    - {name: x,")].join("\n");
    const t0 = Date.now();
    extractImageReferences(ci, ".gitlab-ci.yml");
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  // Compose and GitHub Actions services are MAPS of name -> {image: ...}: the
  // image: path reads them, and the list reader must add nothing.
  it("reads a compose or GitHub Actions services map exactly once", () => {
    const compose = [
      "services:",
      "  name:",
      "    image: evilns/tool:6.6.6",
      "  web:",
      "    image: nginx:1.27",
      "    command: [\"nginx\"]",
    ].join("\n");
    expect(extractImageReferences(compose, "docker-compose.yml").map((r) => r.raw)).toEqual(["evilns/tool:6.6.6", "nginx:1.27"]);
    expect(hits(compose, "docker-compose.yml")).toHaveLength(1);
    const gha = [
      "jobs:",
      "  test:",
      "    services:",
      "      scanner:",
      "        image: evilns/tool:6.6.6",
      "        ports:",
      "          - 5432:5432",
      "    steps:",
      "      - name: evilns/tool:6.6.6",
      "      - uses: actions/checkout@v4",
    ].join("\n");
    expect(extractImageReferences(gha, ".github/workflows/ci.yml").map((r) => r.raw)).toEqual(["evilns/tool:6.6.6"]);
    expect(hits(gha, ".github/workflows/ci.yml")).toHaveLength(1);
  });

  it("does not read a name: or a bare item under any other list", () => {
    const yaml = [
      "steps:",
      "  - name: evilns/tool:6.6.6",
      "  - evilns/tool:6.6.6",
      "containers:",
      "  - name: evilns/tool:6.6.6",
      "services:",
      "  - name: ok",
      "variables:",
      "  - name: evilns/tool:6.6.6",
      "  - evilns/tool:6.6.6",
    ].join("\n");
    expect(extractImageReferences(yaml, ".gitlab-ci.yml").map((r) => r.raw)).toEqual(["ok"]);
    expect(hits(yaml, ".gitlab-ci.yml")).toEqual([]);
  });

  it("stays linear on hostile YAML and Dockerfile input", () => {
    // A long whitespace run with no key after it is the classic shape for
    // `\s*-?\s*`, which splits the run every way before failing.
    const yaml = "image:\n" + "  repository: a\n".repeat(100_000) + ("image: {" + "a,".repeat(200_000) + "\n")
      + " ".repeat(200_000) + "x\n" + "- " + " ".repeat(200_000) + "x\n"
      // services list items: long keys, whitespace runs, many items.
      + "services:\n" + "  - " + "a".repeat(200_000) + " b\n" + "    name" + " ".repeat(200_000) + "x\n"
      + "  - name:" + " ".repeat(200_000) + "\n" + "  - x:1\n".repeat(100_000)
      + "services: [" + "a,".repeat(200_000) + "\n";
    const docker = "FROM alpine:3\n" + ("RUN " + "--mount=from=,".repeat(50_000) + "\n").repeat(4)
      + "COPY " + "--a ".repeat(100_000) + "x\n";
    const t0 = Date.now();
    extractImageReferences(yaml, "values.yaml");
    extractImageReferences(docker, "Dockerfile");
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});
