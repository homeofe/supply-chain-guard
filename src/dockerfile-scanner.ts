/**
 * Dockerfile and container configuration scanner.
 *
 * Detects supply-chain risks in Dockerfile, docker-compose.yml, and
 * related container configuration files.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry } from "./types.js";
import {
  MAX_CORRELATED_EVIDENCE_CHARS,
  truncateMatch,
  validatePatternSet,
} from "./patterns.js";
import { matchPatternInFile } from "./pattern-scanner.js";

// ---------------------------------------------------------------------------
// Global npm install: pinned or not?
// ---------------------------------------------------------------------------

/** npm flags that carry no package name. */
const NPM_FLAG_RE = /^-/;

/** Shell operators that end the npm command (`&& npm cache clean --force`). */
const SHELL_SEPARATOR_RE = /^(?:&&|\|\||;|\||&|\\)$/;

/**
 * A local artifact rather than a registry package: a path, a packed tarball, or
 * an explicit `file:` specifier. Installing your own build output globally is
 * not the mutable-registry-dependency this rule is about.
 */
const LOCAL_ARTIFACT_RE = /^(?:file:|\.{0,2}[\\/]|[A-Za-z]:[\\/])|\.(?:tgz|tar\.gz)$/;

/**
 * An EXACT version selector: `9`, `11.18.0`, `1.2.3-rc.1`, or a `@scope/name`
 * spec ending in one. Range operators (`^`, `~`, `>`, `*`, `x`) and dist-tags
 * (`latest`, `next`, `beta`) are NOT exact - both can resolve to a different
 * package on the next build, which is exactly what this rule warns about.
 */
function isPinnedSpec(spec: string): boolean {
  if (LOCAL_ARTIFACT_RE.test(spec)) return true;
  // Ignore a leading scope "@" so @scope/name@1.2.3 splits on the right "@".
  const at = spec.lastIndexOf("@");
  if (at <= 0) return false; // no version at all: `npm i -g pnpm`
  const version = spec.slice(at + 1);
  return /^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$/.test(version);
}

interface LocalStructuralMatch {
  start: number;
  end: number;
  evidence: string;
}

type DockerMatchRange = Pick<LocalStructuralMatch, "start" | "end">;

function boundedStructuralMatch(
  content: string,
  start: number,
  end: number,
): LocalStructuralMatch {
  return {
    start,
    end,
    evidence: content.slice(
      start,
      Math.min(end, start + MAX_CORRELATED_EVIDENCE_CHARS),
    ),
  };
}

function* matchDockerLines(
  content: string,
  findMatch: (line: string) => DockerMatchRange | undefined,
): Iterable<LocalStructuralMatch> {
  let lineStart = 0;
  while (lineStart <= content.length) {
    const newline = content.indexOf("\n", lineStart);
    const lineEnd = newline === -1 ? content.length : newline;
    const line = content.slice(lineStart, lineEnd);
    const match = findMatch(line);
    if (match) {
      yield boundedStructuralMatch(
        content,
        lineStart + match.start,
        lineStart + match.end,
      );
    }
    if (newline === -1) break;
    lineStart = newline + 1;
  }
}

function hasDotTerminator(value: string): boolean {
  return /[\r\u2028\u2029]/u.test(value);
}

function preferLegacyMatch(
  current: DockerMatchRange | undefined,
  candidate: DockerMatchRange,
): DockerMatchRange {
  if (!current || candidate.start < current.start) return candidate;
  if (candidate.start === current.start && candidate.end > current.end) {
    return candidate;
  }
  return current;
}

const DOCKER_INTERPRETER_AT_PIPE = /\s*(?:bash|sh|python|node|perl)/iy;

const dockerCurlPipeMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (
  content,
) =>
  matchDockerLines(content, (line) => {
    const tokens = /RUN\s+|(?:curl|wget)\s+|\||[\r\u2028\u2029]/gi;
    let activeRun = -1;
    let pendingRun = -1;
    let best: DockerMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      if (value === "|") {
        if (pendingRun !== -1) {
          DOCKER_INTERPRETER_AT_PIPE.lastIndex = token.index + 1;
          if (DOCKER_INTERPRETER_AT_PIPE.exec(line)) {
            best = preferLegacyMatch(best, {
              start: pendingRun,
              end: DOCKER_INTERPRETER_AT_PIPE.lastIndex,
            });
          }
        }
        pendingRun = -1;
      } else if (/^[\r\u2028\u2029]$/u.test(value)) {
        activeRun = -1;
      } else if (/^(?:curl|wget)/i.test(value)) {
        if (
          activeRun !== -1 &&
          (pendingRun === -1 || activeRun < pendingRun)
        ) {
          pendingRun = activeRun;
        }
        // The downloader's own \s+ may consume a dot terminator. It belongs
        // to this completed stage, but the RUN start cannot reach a later
        // downloader beyond it.
        if (hasDotTerminator(value)) activeRun = -1;
      } else {
        // A later RUN token that consumes a dot terminator replaces an older
        // start: the older RUN's dot gap cannot cross that terminator.
        if (activeRun === -1 || hasDotTerminator(value)) {
          activeRun = token.index;
        }
      }
    }
    return best;
  });

const dockerSuidMatcher: NonNullable<PatternEntry["correlatedMatcher"]> = (
  content,
) =>
  matchDockerLines(content, (line) => {
    const tokens =
      /RUN\s+|chmod\s+[ugo]*\+s|[\r\u2028\u2029]/gi;
    let activeRun = -1;
    let best: DockerMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      if (/^[\r\u2028\u2029]$/u.test(value)) {
        activeRun = -1;
      } else if (/^RUN/i.test(value)) {
        if (activeRun === -1 || hasDotTerminator(value)) {
          activeRun = token.index;
        }
      } else {
        if (activeRun !== -1) {
          best = preferLegacyMatch(best, {
            start: activeRun,
            end: tokens.lastIndex,
          });
        }
        if (hasDotTerminator(value)) activeRun = -1;
      }
    }
    return best;
  });

const dockerAptNoVerifyMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = (content) =>
  matchDockerLines(content, (line) => {
    const tokens =
      /RUN\s+|apt(?:-get)?\s+|--allow-unauthenticated|--force-yes|[\r\u2028\u2029]/gi;
    let activeRun = -1;
    let aptRun = -1;
    let firstForce = -1;
    let bestApt: DockerMatchRange | undefined;
    let token: RegExpExecArray | null;

    while ((token = tokens.exec(line)) !== null) {
      const value = token[0]!;
      const lower = value.toLowerCase();
      if (/^[\r\u2028\u2029]$/u.test(value)) {
        activeRun = -1;
        aptRun = -1;
      } else if (lower === "--force-yes") {
        if (firstForce === -1) firstForce = token.index;
      } else if (lower === "--allow-unauthenticated") {
        if (aptRun !== -1) {
          bestApt = preferLegacyMatch(bestApt, {
            start: aptRun,
            end: tokens.lastIndex,
          });
        }
      } else if (lower.startsWith("apt")) {
        const associatedRun = activeRun;
        if (hasDotTerminator(value)) {
          // The separator is valid inside apt's \s+, so this apt stage may
          // survive it. Earlier apt and RUN stages may not.
          aptRun = associatedRun;
          activeRun = -1;
        } else if (
          associatedRun !== -1 &&
          (aptRun === -1 || associatedRun < aptRun)
        ) {
          aptRun = associatedRun;
        }
      } else if (hasDotTerminator(value)) {
        // This is RUN\s+ containing a dot terminator. It starts a fresh RUN
        // stage and invalidates an older apt completion stage.
        activeRun = token.index;
        aptRun = -1;
      } else if (activeRun === -1) {
        activeRun = token.index;
      }
    }

    if (bestApt && (firstForce === -1 || bestApt.start < firstForce)) {
      return bestApt;
    }
    return firstForce === -1
      ? bestApt
      : { start: firstForce, end: firstForce + "--force-yes".length };
  });
/**
 * True when a global npm install leaves at least one package UNPINNED.
 *
 * The rule's own recommendation has always been "pin the global package
 * version", yet the pattern fired on `RUN npm install -g pnpm@9` and
 * `RUN npm install -g npm@11.18.0` - installs that already do exactly what the
 * recommendation asks (27 such findings in one Elvatis repo alone). Matching
 * the command shape says nothing about the risk; the package SPECS do.
 */
export function isUnpinnedGlobalInstall(specs: string): boolean {
  const tokens = specs
    .trim()
    .split(/\s+/)
    .filter((t) => t !== "");

  const packages: string[] = [];
  for (const token of tokens) {
    if (SHELL_SEPARATOR_RE.test(token)) break; // rest belongs to another command
    if (NPM_FLAG_RE.test(token)) continue;
    packages.push(token);
  }

  // No parseable package spec (e.g. a shell variable): keep reporting.
  if (packages.length === 0) return true;
  return packages.some((p) => !isPinnedSpec(p));
}

const DOCKER_NPM_GLOBAL_PREFIX =
  /RUN\s+npm\s+(?:install|i|add)\s+(?:-g|--global|--location=global)\s+(?=.)/gi;

const dockerNpmGlobalMatcher: NonNullable<
  PatternEntry["correlatedMatcher"]
> = (content) =>
  matchDockerLines(content, (line) => {
    const matchEnd = line.length;
    const lastInternalTerminator = Math.max(
      line.lastIndexOf("\r", matchEnd - 1),
      line.lastIndexOf("\u2028", matchEnd - 1),
      line.lastIndexOf("\u2029", matchEnd - 1),
    );

    DOCKER_NPM_GLOBAL_PREFIX.lastIndex = 0;
    let prefix: RegExpExecArray | null;
    while ((prefix = DOCKER_NPM_GLOBAL_PREFIX.exec(line)) !== null) {
      const specsStart = DOCKER_NPM_GLOBAL_PREFIX.lastIndex;
      if (specsStart <= lastInternalTerminator || specsStart >= matchEnd) {
        continue;
      }

      DOCKER_NPM_GLOBAL_PREFIX.lastIndex = 0;
      return isUnpinnedGlobalInstall(line.slice(specsStart, matchEnd))
        ? { start: prefix.index, end: matchEnd }
        : undefined;
    }
    DOCKER_NPM_GLOBAL_PREFIX.lastIndex = 0;
    return undefined;
  });

// ---------------------------------------------------------------------------
// FROM instructions: one structural parser, three pinning verdicts
// ---------------------------------------------------------------------------

/**
 * WHY A PARSER AND NOT A WIDER REGEX.
 *
 * The released rule was one regex,
 * `FROM\s+(?!scratch)\S+:(?:latest|stable|lts|current|mainline)(?:\s|$)`, and it
 * was narrower than its own five words:
 *
 * - `\S+` binds to the FIRST token after FROM, so
 *   `FROM --platform=$BUILDPLATFORM node:latest` scanned clean despite carrying
 *   a literal `:latest`, and passed `--fail-on high` with exit code 0.
 * - the alternation ended at `(?:\s|$)`, so the suffixed upstream channel tags
 *   (`node:lts-alpine`, `nginx:stable-alpine`, `nginx:mainline-alpine`) scanned
 *   clean while their bare forms flagged. The suffixed forms are the ones people
 *   actually write.
 * - `(?!scratch)` had no token boundary, so `FROM scratch-base:latest` and
 *   `FROM scratchpad:latest` scanned clean.
 *
 * Measured on the released rule over 19 representative FROM lines: 5 flagged,
 * and the 5 were exactly the five bare literal words.
 *
 * Widening the regex cannot fix this. Two of the three misses are structural (a
 * flag token, a build-stage name), and this repository's own denial-of-service
 * guard, `validatePatternSet` in src/patterns.ts, refuses the obvious widened
 * forms at module load because they contain a broad unbounded consuming gap.
 * `correlatedMatcher` is the mechanism this file already uses for exactly that
 * reason (DOCKER_CURL_PIPE, DOCKER_APT_NO_VERIFY), so the FROM rules use it too.
 * One parser produces all three verdicts, which is why the rules can no longer
 * disagree about what a build-stage reference is.
 */

/**
 * TIERING AND SEVERITY. This is an owner-level policy choice, recorded here
 * because this is where the next reader meets it. The options and the reasoning
 * are in docs/ARCHITECTURE.md, "Base image pinning".
 *
 * A base image reference is sorted into exactly one verdict:
 *
 *   digest pinned      `FROM node:22-alpine@sha256:<64 hex>`  no finding
 *   scratch            `FROM scratch`                         no finding
 *   no tag, no digest  `FROM ubuntu`             DOCKER_NO_TAG          high
 *   moving channel tag `FROM node:lts-alpine`    DOCKER_UNPINNED_BASE   high
 *   tag, but no digest `FROM node:20-alpine`     DOCKER_TAG_NOT_DIGEST  low
 *
 * The alternative was one rule at `high` for every FROM line without a digest.
 * It was not taken, for a measured reason: `high` is what the DEFAULT gate fails
 * on (`getReportExitCode` in src/reporter.ts returns 1 when `summary.high > 0`),
 * so a single high tier would flip every ordinary version-tagged Dockerfile in
 * every consumer from pass to fail in one release, for a risk that has not
 * changed. The split follows the precedent this codebase already set for the
 * same question about GitHub Actions references: src/github-actions-scanner.ts
 * reports a branch-like ref as GHA_UNPINNED_ACTION (medium) and a version tag
 * that is not a commit SHA as GHA_TAG_NOT_SHA (low). DOCKER_TAG_NOT_DIGEST is
 * the Docker analogue of GHA_TAG_NOT_SHA and carries the same `low`.
 *
 * What that costs and who pays it: the default gate, `--fail-on high` and
 * `--fail-on medium` are unchanged by this tier; `--fail-on low`,
 * `--fail-on info` and the risk score (weight 1 per finding, see
 * SEVERITY_WEIGHTS in src/risk-engine.ts) are not. A consumer who wants the
 * digest policy enforced raises the gate to `--fail-on low`; a consumer who does
 * not want the tier at all sets `rules.disable: [DOCKER_TAG_NOT_DIGEST]` in
 * .supply-chain-guard.yml, or reassigns it through `rules.severityOverrides`.
 */

/**
 * DELIBERATE SCOPE LIMIT: Compose `image:` values.
 *
 * `isDockerFile()` admits docker-compose.yml, so the file is opened and read,
 * but every rule in DOCKERFILE_PATTERNS is anchored on a Dockerfile instruction
 * keyword and none of them can match Compose syntax. That is stated in each
 * FROM rule's `description`, in README.md and in docs/ARCHITECTURE.md rather
 * than left to be discovered, because a file that is read by rules which
 * structurally cannot match it looks like coverage and is not.
 */

/** Tag words that name a MOVING CHANNEL rather than a specific release. */
const MUTABLE_CHANNEL_TAGS: ReadonlySet<string> = new Set([
  "latest",
  "stable",
  "lts",
  "current",
  "mainline",
]);

/**
 * A digest that actually pins.
 *
 * The OCI image specification writes a digest as `algorithm ":" encoded`, and
 * registers exactly two algorithms: sha256 (64 hex characters) and sha512 (128).
 * The length is part of the test on purpose, so a truncated placeholder such as
 * `@sha256:abc...` is NOT read as a pin. It identifies no image and the daemon
 * rejects it, so treating it as pinned would report a broken reference as safe.
 */
const PINNED_DIGEST_RE =
  /^(?:sha256:[0-9a-fA-F]{64}|sha512:[0-9a-fA-F]{128})$/;

/**
 * How many characters of one FROM instruction are parsed, and how much of a
 * continuation chain is joined.
 *
 * The bound exists so that a single attacker-supplied multi-megabyte line, or a
 * file of a million continuation lines, cannot turn this matcher superlinear.
 * 1024 is roughly double the longest FROM instruction the reference grammar can
 * produce: an image name is capped at 255 characters, a tag at 128, a sha512
 * digest costs 136 with its separator, `--platform=linux/arm64/v8` about 25,
 * and ` AS <stage>` a few dozen more, which totals under 600. An instruction
 * longer than this bound is therefore not a legal reference; it is parsed as far
 * as the bound and then produces no finding, which is asserted by the test
 * "does not classify a FROM instruction longer than the parse bound".
 */
const MAX_FROM_INSTRUCTION_CHARS = 1024;

/** A Dockerfile comment line. Docker removes these before joining continuations. */
const DOCKER_COMMENT_LINE_RE = /^[ \t]*#/;

/**
 * `FROM` as the instruction of the line. Group 1 is the indent, group 2 the rest.
 *
 * Deliberately NOT anchored with `$`. JavaScript's `.` stops at a line
 * terminator, so `FROM node:latest\rEXTRA` would fail a `$`-anchored match
 * entirely and the literal `:latest` would scan clean. Without the anchor the
 * reference is read up to the terminator and still classified, which is the
 * same evasion the other rules in this file guard against (see hasDotTerminator
 * above). Covered by "classifies a FROM instruction carrying an embedded line
 * terminator".
 */
const FROM_INSTRUCTION_RE = /^([ \t]*)FROM[ \t]+(.*)/i;

/** A FROM instruction flag, for example `--platform=linux/amd64`. */
const FROM_FLAG_RE = /^--[A-Za-z][A-Za-z0-9-]*(?:=.*)?$/;

/**
 * A reference that is WHOLLY a build argument or environment variable. Its value
 * is not visible to a file-local scan and may itself carry a digest, so
 * classifying it would be a guess. The ARG default is deliberately not resolved
 * either: `--build-arg` overrides it at build time, so the default is not
 * authoritative. Such a reference produces no finding, in either direction.
 */
const WHOLLY_VARIABLE_REF_RE = /^\$(?:\{[^{}]*\}|[A-Za-z_][A-Za-z0-9_]*)$/;

/** A line continued by a trailing backslash. */
const LINE_CONTINUATION_RE = /\\[ \t]*$/;

interface DockerLogicalLine {
  /** Offset of the first character of the instruction's first physical line. */
  start: number;
  /** Offset just past that first physical line, so evidence never spans lines. */
  firstLineEnd: number;
  /** Comment lines removed, continuations joined, length bounded. */
  text: string;
}

/**
 * Yield logical Dockerfile lines: comment lines dropped, backslash
 * continuations joined, in that order, which is the order the daemon applies.
 *
 * Tracking continuations is not a nicety. Without it, the second line of
 * `RUN echo x \` / `FROM node:latest` reads as a FROM instruction when it is an
 * argument to RUN.
 */
function* iterateDockerLogicalLines(
  content: string,
): Iterable<DockerLogicalLine> {
  let index = 0;
  let pending: DockerLogicalLine | undefined;

  for (;;) {
    if (index > content.length) break;
    const newline = content.indexOf("\n", index);
    const lineEnd = newline === -1 ? content.length : newline;
    let rawEnd = lineEnd;
    if (rawEnd > index && content.charCodeAt(rawEnd - 1) === 0x0d) rawEnd--;
    const raw = content.slice(index, rawEnd);

    if (!DOCKER_COMMENT_LINE_RE.test(raw)) {
      const continues = LINE_CONTINUATION_RE.test(raw);
      const body = continues ? raw.replace(LINE_CONTINUATION_RE, "") : raw;
      pending ??= { start: index, firstLineEnd: rawEnd, text: "" };
      const budget = MAX_FROM_INSTRUCTION_CHARS - pending.text.length;
      if (budget > 0) pending.text += body.slice(0, budget);
      if (!continues) {
        yield pending;
        pending = undefined;
      }
    }

    if (newline === -1) break;
    index = newline + 1;
  }

  if (pending !== undefined) yield pending;
}

interface FromInstruction {
  /** Offset of the FROM keyword. */
  start: number;
  /** Offset just past the reported evidence, always on the FROM keyword's line. */
  end: number;
  /** The image reference token with FROM flags removed, "" when absent. */
  reference: string;
  /** Lower-cased build-stage name this instruction declares, if any. */
  stage: string | undefined;
}

function parseFromInstruction(
  line: DockerLogicalLine,
): FromInstruction | undefined {
  const match = FROM_INSTRUCTION_RE.exec(line.text);
  if (match === null) return undefined;

  const start = line.start + match[1]!.length;
  const end = Math.min(
    line.firstLineEnd,
    start + MAX_FROM_INSTRUCTION_CHARS,
  );
  if (end <= start) return undefined;

  const tokens = match[2]!.split(/[ \t]+/).filter((token) => token !== "");
  let cursor = 0;
  while (cursor < tokens.length && FROM_FLAG_RE.test(tokens[cursor]!)) cursor++;

  // Docker stage names are matched case-insensitively, so normalise once here.
  const stage =
    tokens.length > cursor + 2 && tokens[cursor + 1]!.toLowerCase() === "as"
      ? tokens[cursor + 2]!.toLowerCase()
      : undefined;

  return { start, end, reference: tokens[cursor] ?? "", stage };
}

type BaseImagePinning =
  | "digest-pinned"
  | "scratch"
  | "no-tag"
  | "mutable-channel"
  | "tag-without-digest";

/**
 * Sort one image reference into exactly one pinning verdict, or undefined when
 * the reference cannot be judged from the file alone.
 *
 * Reference grammar: `[registry[:port]/]name[:tag][@digest]`. The port colon is
 * distinguished from the tag colon by requiring the tag colon to come after the
 * last `/`, which is why `registry.example.com:5000/team/app` is not read as a
 * tag of `5000/team/app`.
 */
function classifyBaseImageReference(
  reference: string,
): BaseImagePinning | undefined {
  if (reference === "") return undefined;
  if (WHOLLY_VARIABLE_REF_RE.test(reference)) return undefined;

  const at = reference.lastIndexOf("@");
  const namePart = at === -1 ? reference : reference.slice(0, at);
  if (at !== -1 && PINNED_DIGEST_RE.test(reference.slice(at + 1))) {
    return "digest-pinned";
  }

  const slash = namePart.lastIndexOf("/");
  const colon = namePart.lastIndexOf(":");
  const tagged = colon > slash;
  const tag = tagged ? namePart.slice(colon + 1) : "";
  const name = tagged ? namePart.slice(0, colon) : namePart;

  // `scratch` is the reserved empty image and cannot be pinned. It is exempt
  // only as a WHOLE token, which is what `scratch-base` and `scratchpad` broke.
  if (at === -1 && !tagged && name.toLowerCase() === "scratch") return "scratch";
  if (at === -1 && !tagged) return "no-tag";

  // A moving channel tag composes as `<channel>-<variant>` upstream
  // (node:lts-alpine, nginx:stable-alpine), so the FIRST hyphen-separated
  // component is what decides. Only that leading position counts: a trailing
  // component is a variant name, not a channel.
  const channel = tag.split("-", 1)[0]!.toLowerCase();
  if (MUTABLE_CHANNEL_TAGS.has(channel)) return "mutable-channel";

  // Everything left is referenced by something that is not an immutable digest:
  // a version tag, an arbitrary tag, or a malformed digest.
  return "tag-without-digest";
}

/**
 * Build the structural matcher for one pinning verdict.
 *
 * Build-stage names are collected in file order and a reference resolving to an
 * already declared stage is skipped: `FROM builder` after `... AS builder` names
 * a stage in this build, not a registry image, and a stage cannot be digest
 * pinned. Order matters, because Docker resolves only stages declared ABOVE the
 * instruction.
 */
function fromInstructionMatcher(
  wanted: BaseImagePinning,
): NonNullable<PatternEntry["correlatedMatcher"]> {
  return function* matchFromInstructions(content: string) {
    const declaredStages = new Set<string>();

    for (const line of iterateDockerLogicalLines(content)) {
      const instruction = parseFromInstruction(line);
      if (instruction === undefined) continue;

      const referencesStage = declaredStages.has(
        instruction.reference.toLowerCase(),
      );
      if (instruction.stage !== undefined) declaredStages.add(instruction.stage);
      if (referencesStage) continue;

      if (classifyBaseImageReference(instruction.reference) !== wanted) continue;
      yield boundedStructuralMatch(content, instruction.start, instruction.end);
    }
  };
}

// ---------------------------------------------------------------------------
// Dockerfile patterns
// ---------------------------------------------------------------------------

export const DOCKERFILE_PATTERNS: PatternEntry[] = [
  {
    name: "docker-curl-pipe",
    pattern:
      "RUN\\s+.*(?:curl|wget)\\s+[^|]*\\|\\s*(?:bash|sh|python|node|perl)",
    description:
      "Dockerfile downloads and pipes remote content to a shell (remote code execution risk)",
    severity: "critical",
    rule: "DOCKER_CURL_PIPE",
    correlatedMatcher: dockerCurlPipeMatcher,
  },
  {
    name: "docker-unpinned-base",
    // Shape only, kept so the rule still reads as a pattern and still passes
    // validatePatternSet. The verdict comes from fromInstructionMatcher; editing
    // this string changes nothing that is reported.
    pattern:
      "FROM\\s+\\S*:(?:latest|stable|lts|current|mainline)",
    description:
      "Dockerfile base image is referenced by a moving channel tag (latest, stable, lts, current, mainline, " +
      "including variant forms such as stable-alpine). The image behind such a tag is replaced without notice, " +
      "so the same Dockerfile builds different software. Compose image: values are out of scope for every " +
      "Docker rule; see docs/ARCHITECTURE.md.",
    severity: "high",
    rule: "DOCKER_UNPINNED_BASE",
    correlatedMatcher: fromInstructionMatcher("mutable-channel"),
  },
  {
    name: "docker-no-tag",
    // Shape only; see the note on docker-unpinned-base.
    pattern:
      "FROM\\s+(?!scratch)[a-z][a-z0-9._/-]*\\s*$",
    description:
      "Dockerfile FROM without a tag or digest. Defaults to :latest, which is mutable. A reference to a build " +
      "stage declared earlier in the same file is not a registry image and is not reported. Compose image: " +
      "values are out of scope for every Docker rule; see docs/ARCHITECTURE.md.",
    severity: "high",
    rule: "DOCKER_NO_TAG",
    correlatedMatcher: fromInstructionMatcher("no-tag"),
  },
  {
    name: "docker-tag-not-digest",
    // Shape only; see the note on docker-unpinned-base. Kept admissible to
    // hasBroadUnboundedConsumingGap on its own, so that removing the matcher
    // shows up as a wrong verdict in the tests rather than as an import error
    // that vitest reports as "no tests", which reads far too much like a pass.
    pattern:
      "FROM\\s+\\S+:\\S+",
    description:
      "Dockerfile base image is referenced by tag rather than by an immutable digest, so the same tag can " +
      "resolve to a different image on the next build. Reported at low severity: it is a reproducibility gap, " +
      "not a moving channel. Compose image: values are out of scope for every Docker rule; see " +
      "docs/ARCHITECTURE.md.",
    severity: "low",
    rule: "DOCKER_TAG_NOT_DIGEST",
    correlatedMatcher: fromInstructionMatcher("tag-without-digest"),
  },
  {
    name: "docker-http-source",
    pattern:
      "(?:ADD|COPY)\\s+https?://",
    description:
      "Dockerfile downloads files via ADD/COPY from an HTTP(S) URL without checksum verification",
    severity: "high",
    rule: "DOCKER_HTTP_SOURCE",
  },
  {
    name: "docker-secrets-build",
    pattern:
      "(?:ENV|ARG)\\s+\\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIALS|AUTH)\\w*\\s*=\\s*\\S+",
    description:
      "Hardcoded secret in Dockerfile ENV/ARG. Secrets leak into image layers and history.",
    severity: "high",
    rule: "DOCKER_SECRETS_BUILD",
  },
  {
    name: "docker-npm-global",
    // Group 1 is everything after the global flag; isUnpinnedGlobalInstall()
    // decides whether those package specs are actually unpinned (v5.18).
    pattern:
      "RUN\\s+npm\\s+(?:install|i|add)\\s+(?:-g|--global|--location=global)\\s+(.+)$",
    description:
      "Unpinned global npm install in Dockerfile. Without a version the image installs " +
      "whatever the registry serves at build time, so the same Dockerfile can produce a " +
      "different (or compromised) package on the next build.",
    severity: "medium",
    rule: "DOCKER_NPM_GLOBAL",
    correlatedMatcher: dockerNpmGlobalMatcher,
  },
  {
    name: "docker-untrusted-registry",
    pattern:
      "FROM\\s+(?!(?:docker\\.io|ghcr\\.io|gcr\\.io|mcr\\.microsoft\\.com|public\\.ecr\\.aws|quay\\.io|registry\\.access\\.redhat\\.com|scratch))[a-z0-9]+\\.[a-z]{2,}/",
    description:
      "Dockerfile pulls a base image from a non-standard container registry",
    severity: "medium",
    rule: "DOCKER_UNTRUSTED_REGISTRY",
  },
  {
    name: "docker-run-chmod-suid",
    pattern:
      "RUN\\s+.*chmod\\s+[ugo]*\\+s",
    description:
      "Dockerfile sets SUID/SGID bit on a file. This can be used for privilege escalation.",
    severity: "high",
    rule: "DOCKER_SUID",
    correlatedMatcher: dockerSuidMatcher,
  },
  {
    name: "docker-apt-no-verify",
    pattern:
      "RUN\\s+.*apt(?:-get)?\\s+.*--allow-unauthenticated|--force-yes",
    description:
      "Dockerfile disables APT package signature verification. Packages may be tampered with.",
    severity: "high",
    rule: "DOCKER_APT_NO_VERIFY",
    correlatedMatcher: dockerAptNoVerifyMatcher,
  },
];

validatePatternSet("DOCKERFILE_PATTERNS", DOCKERFILE_PATTERNS);

/** Files that this scanner checks */
const DOCKER_FILE_PATTERNS = [
  /^Dockerfile$/i,
  /^Dockerfile\..+$/i,
  /^docker-compose\.ya?ml$/i,
  /^\.dockerignore$/i,
  /^Containerfile$/i,
];

/**
 * Check whether a filename is a Docker-related file.
 */
export function isDockerFile(filename: string): boolean {
  return DOCKER_FILE_PATTERNS.some((re) => re.test(filename));
}

/**
 * Scan a single Docker-related file for supply-chain risks.
 */
export function scanDockerFile(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of DOCKERFILE_PATTERNS) {
    const hits = matchPatternInFile(pattern, content, relativePath, findings, "i");
    for (const hit of hits ?? []) {
      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severity,
        file: relativePath,
        line: hit.line,
        match: truncateMatch(hit.text),
        recommendation: getDockerRecommendation(pattern.rule),
      });
    }
  }

  return findings;
}

/**
 * Scan a directory for all Docker-related files.
 */
export function scanDockerFiles(dir: string): Finding[] {
  const findings: Finding[] = [];

  // Check root-level Docker files
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!isDockerFile(entry.name)) continue;

      const fullPath = path.join(dir, entry.name);
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        findings.push(...scanDockerFile(content, entry.name));
      } catch {
        // skip unreadable files
      }
    }
  } catch {
    // directory not readable
  }

  return findings;
}

function getDockerRecommendation(rule: string): string {
  const map: Record<string, string> = {
    DOCKER_CURL_PIPE:
      "Download files to disk first, verify their checksum, then execute. Never pipe remote content to a shell.",
    DOCKER_UNPINNED_BASE:
      "Replace the channel tag with a specific release and pin it by digest: " +
      "FROM node:22-alpine@sha256:<64 hex>. A channel tag moves under you, so the build is not reproducible " +
      "and a compromised republish of that tag lands silently.",
    DOCKER_NO_TAG:
      "Always specify a tag or digest for base images. Using no tag defaults to :latest which is mutable.",
    DOCKER_TAG_NOT_DIGEST:
      "Add the digest alongside the tag: FROM node:22-alpine@sha256:<64 hex>. The tag stays readable and the " +
      "digest makes the build reproducible. Pair it with an automated bump (Dependabot or Renovate) so the pin " +
      "does not silently freeze, and see docs/ARCHITECTURE.md if this tier is noise for your project.",
    DOCKER_HTTP_SOURCE:
      "Download files in a RUN step with checksum verification instead of using ADD with URLs.",
    DOCKER_SECRETS_BUILD:
      "Use Docker BuildKit secrets (--mount=type=secret) or runtime environment variables instead of hardcoding secrets.",
    DOCKER_NPM_GLOBAL:
      "Pin every globally installed package to an exact version (npm install -g pnpm@9.15.0), " +
      "or install locally with npx. A bare name, a dist-tag (@latest) and a range (@^9) all resolve " +
      "at build time, so the image is not reproducible and a hijacked release lands silently.",
    DOCKER_UNTRUSTED_REGISTRY:
      "Use images from trusted registries (Docker Hub, GHCR, GCR, ECR) or verify the registry's authenticity.",
    DOCKER_SUID:
      "Avoid setting SUID/SGID bits in containers. Use capabilities or non-root users instead.",
    DOCKER_APT_NO_VERIFY:
      "Never disable APT signature verification. Fix GPG key issues instead.",
  };
  return map[rule] ?? "Review this Dockerfile instruction manually.";
}
