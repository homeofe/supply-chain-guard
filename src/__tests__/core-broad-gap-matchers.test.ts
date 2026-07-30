import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { performanceBudget } from "./performance-budget.js";
import { CORE_BROAD_GAP_RULES } from "../broad-gap-pattern-matchers.js";
import { isPatternApplicableToFile } from "../pattern-applicability.js";
import {
  ALL_PATTERN_SETS,
  isLikelyRealSecretValue,
  matchPatternInContent,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";

const shippedRule = (rule: string): PatternEntry => {
  const entry = ALL_PATTERN_SETS
    .flatMap(([, patterns]) => patterns)
    .find((candidate) => candidate.rule === rule);
  if (!entry) throw new Error(`Missing shipped rule: ${rule}`);
  return entry as PatternEntry;
};

const legacyRegexOnly = (entry: PatternEntry): PatternEntry => ({
  ...entry,
  correlatedMatcher: undefined,
  ...(entry.rule === "IAC_HARDCODED_SECRET"
    ? { valueFilter: isLikelyRealSecretValue, valueGroup: 1 }
    : {}),
});

interface ParityCase {
  rule: string;
  flags: "g" | "i";
  content: string;
  expectedLines: number[];
  expectedStarts?: number[];
  expectedEvidence?: string[];
}

function absoluteRegexStarts(
  content: string,
  hits: readonly { line: number; match: RegExpMatchArray }[],
): number[] {
  const lineStarts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") lineStarts.push(index + 1);
  }
  return hits.map((hit) =>
    lineStarts[hit.line - 1]! + (hit.match.index ?? 0));
}

const parityCases: ParityCase[] = [
  { rule: "EVAL_HEX", flags: "g", content: "const x = eval(Buffer.from(payload, 'hex'))", expectedLines: [1] },
  { rule: "EVAL_HEX", flags: "g", content: "eval(Buffer.from(,'hex'))", expectedLines: [] },
  { rule: "EVAL_HEX", flags: "g", content: "eval(Buffer.from(payload), 'hex')", expectedLines: [] },
  { rule: "ENV_EXFILTRATION", flags: "g", content: "process.env.SECRET + fetch(url)", expectedLines: [1] },
  { rule: "ENV_EXFILTRATION", flags: "g", content: "axios.post(url, process.env.SECRET)", expectedLines: [1] },
  { rule: "ENV_EXFILTRATION", flags: "g", content: "process.env.SECRET; fetch(url)", expectedLines: [] },
  { rule: "DNS_EXFILTRATION", flags: "g", content: "dns.resolve(name + process.env.SECRET)", expectedLines: [1] },
  { rule: "DNS_EXFILTRATION", flags: "g", content: "dns.resolve(name)\rprocess.env.SECRET", expectedLines: [] },
  { rule: "SCRIPT_NODE_INLINE", flags: "i", content: "NODE -E \"load HTTPS://x.invalid\"", expectedLines: [1] },
  { rule: "SCRIPT_NODE_INLINE", flags: "i", content: "node -e \"fetchttps", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["node -e \"fetchttp"] },
  { rule: "SCRIPT_NODE_INLINE", flags: "i", content: "node -e \"safe node -e \r\"fetch(url)", expectedLines: [1] },
  { rule: "SCRIPT_NODE_INLINE", flags: "i", content: "node -e \"safe\r fetch(url)\"", expectedLines: [] },
  { rule: "XZ_BUILD_INJECT", flags: "g", content: "gl_cv_host_cpu_c_abi value = value configure.ac", expectedLines: [1] },
  { rule: "XZ_BUILD_INJECT", flags: "g", content: "AM_CONDITIONAL foo gl_INIT", expectedLines: [1] },
  { rule: "XZ_BUILD_INJECT", flags: "g", content: "m4/path/file.m4 data ifnot", expectedLines: [1] },
  { rule: "XZ_BUILD_INJECT", flags: "g", content: ".m4/a.m4 x ifnot", expectedLines: [1], expectedStarts: [1], expectedEvidence: ["m4/a.m4 x ifnot"] },
  { rule: "XZ_BUILD_INJECT", flags: "g", content: "AM_CONDITIONAL\u2028gl_INIT", expectedLines: [] },
  { rule: "CODECOV_EXFIL", flags: "g", content: "codecov reads TOKEN", expectedLines: [1] },
  { rule: "CODECOV_EXFIL", flags: "g", content: "PASSWORD sent to codecov", expectedLines: [1] },
  { rule: "CODECOV_EXFIL", flags: "g", content: "codecov; TOKEN", expectedLines: [] },
  { rule: "SUNBURST_DELAYED_EXEC", flags: "g", content: "setTimeout(first=10000000 + second=20000000)", expectedLines: [1] },
  { rule: "SUNBURST_DELAYED_EXEC", flags: "g", content: "setTimeout(nope) 10000000", expectedLines: [] },
  { rule: "UAPARSER_PREINSTALL_DL", flags: "g", content: "preinstall\": \"curl https://x.invalid/p.exe\"", expectedLines: [1] },
  { rule: "UAPARSER_PREINSTALL_DL", flags: "g", content: "preinstall\": \"curl https://x.invalid/p\" + \".exe\"", expectedLines: [] },
  { rule: "MINI_SHAI_HULUD_PREINSTALL", flags: "g", content: "preinstall\": \"bun run setup.mjs\"", expectedLines: [1] },
  { rule: "MINI_SHAI_HULUD_PREINSTALL", flags: "g", content: "preinstall\": \"bun x setup.mjsetup.mjs\"", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["preinstall\": \"bun x setup.mjsetup.mjs"] },
  { rule: "MINI_SHAI_HULUD_PREINSTALL", flags: "g", content: "preinstall\": \"bun\" + \"setup.mjs\"", expectedLines: [] },
  { rule: "ANTV_WAVE_OTEL_C2", flags: "g", content: "m-kosche.com/x/api/public/otel/v1/traces", expectedLines: [1] },
  { rule: "ANTV_WAVE_OTEL_C2", flags: "g", content: "m-kosche.com\"/api/public/otel/v1/traces", expectedLines: [] },
  { rule: "COA_RC_POSTINSTALL", flags: "g", content: "postinstall\":\"compile.js\"", expectedLines: [1] },
  { rule: "COA_RC_POSTINSTALL", flags: "g", content: "postinstall\":\"Buffer.from(x); exec(x)\"", expectedLines: [1] },
  { rule: "COA_RC_POSTINSTALL", flags: "g", content: "postinstall\":\"Buffer x\rBuffer exec\"", expectedLines: [1] },
  { rule: "COA_RC_POSTINSTALL", flags: "g", content: "postinstall\":\"compile.js; Buffer.from(x); exec(x)\"", expectedLines: [1] },
  { rule: "COA_RC_POSTINSTALL", flags: "g", content: "postinstall\":\"atob x compile.js y spawn\"", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["postinstall\":\"atob x compile.js"] },
  { rule: "COA_RC_POSTINSTALL", flags: "g", content: "postinstall\":\"safe\" Buffer.from(x); exec(x)", expectedLines: [] },
  { rule: "PYPI_ENV_EXFILTRATION", flags: "g", content: "os.environ['TOKEN'] requests.post(url)", expectedLines: [1] },
  { rule: "PYPI_ENV_EXFILTRATION", flags: "g", content: "os.environ['TOKEN']; requests.post(url)", expectedLines: [] },
  { rule: "PYPI_HOSTNAME_EXFIL", flags: "g", content: "socket.gethostname() + http.client", expectedLines: [1] },
  { rule: "PYPI_HOSTNAME_EXFIL", flags: "g", content: "socket.gethostname(); http.client", expectedLines: [] },
  { rule: "BEACON_INTERVAL_FETCH", flags: "i", content: "SETINTERVAL(() => FETCH(url)", expectedLines: [1] },
  { rule: "BEACON_INTERVAL_FETCH", flags: "i", content: "setInterval(x\rfetch(url)", expectedLines: [] },
  { rule: "BEACON_TIMEOUT_FETCH", flags: "i", content: "SETTIMEOUT(() => AXIOS(url)", expectedLines: [1] },
  { rule: "BEACON_TIMEOUT_FETCH", flags: "i", content: "axiosetTimeout(x fetch", expectedLines: [1], expectedStarts: [4], expectedEvidence: ["setTimeout(x fetch"] },
  { rule: "BEACON_TIMEOUT_FETCH", flags: "i", content: "setTimeout(x\u2028axios(url)", expectedLines: [] },
  { rule: "PROTESTWARE_LOCALE_DESTRUCT", flags: "i", content: "TIMEZONE blocked then FS.RM(path)", expectedLines: [1] },
  { rule: "PROTESTWARE_LOCALE_DESTRUCT", flags: "i", content: "timezone\rfs.rm(path)", expectedLines: [] },
  { rule: "PROTESTWARE_GEOIP_DESTRUCT", flags: "i", content: "GEOIP result then EXECSYNC(cmd)", expectedLines: [1] },
  { rule: "PROTESTWARE_GEOIP_DESTRUCT", flags: "i", content: "geoip\u2029execSync(cmd)", expectedLines: [] },
  { rule: "BUILD_PLUGIN_DOWNLOAD", flags: "i", content: "REQUIRE(\"plugin\") then FETCH(url)", expectedLines: [1] },
  { rule: "BUILD_PLUGIN_DOWNLOAD", flags: "i", content: "require(\"plrequire(\"plugin\") x fetch(url)ugin\") x fetch(url)", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["require(\"plrequire(\"plugin\") x fetch(url)ugin\") x fetch"] },
  { rule: "BUILD_PLUGIN_DOWNLOAD", flags: "i", content: "require(\"\") fetch(url)", expectedLines: [] },
  { rule: "BUILD_PLUGIN_DOWNLOAD", flags: "i", content: "require(\"plugin\"); fetch(url)", expectedLines: [] },
  { rule: "BUILD_ENV_EXFIL", flags: "i", content: "PROCESS.ENV.SECRET then FETCH(url)", expectedLines: [1] },
  { rule: "BUILD_ENV_EXFIL", flags: "i", content: "GOT(url) then PROCESS.ENV.SECRET", expectedLines: [1] },
  { rule: "BUILD_ENV_EXFIL", flags: "i", content: "process.env\rfetch(url)", expectedLines: [] },
  { rule: "WORKSPACE_ROOT_POSTINSTALL", flags: "i", content: "\"POSTINSTALL\": \"safe then CURL url\"", expectedLines: [1] },
  { rule: "WORKSPACE_ROOT_POSTINSTALL", flags: "i", content: "\"postinstall\": \"postinstall\": \"safe curl url\"", expectedLines: [1], expectedStarts: [15], expectedEvidence: ["\"postinstall\": \"safe curl"] },
  { rule: "WORKSPACE_ROOT_POSTINSTALL", flags: "i", content: "\"postinstall\": \"safe\" then curl", expectedLines: [] },
  { rule: "WORKSPACE_PRIVATE_PUBLISH", flags: "i", content: "\"PRIVATE\": FALSE, \"PUBLISHCONFIG\": {}", expectedLines: [1] },
  { rule: "WORKSPACE_PRIVATE_PUBLISH", flags: "i", content: "\"private\": false } \"publishConfig\"", expectedLines: [] },
  { rule: "SHAI_HULUD_WORM", flags: "g", content: "child_process x npm y publish z publish", expectedLines: [1] },
  { rule: "SHAI_HULUD_WORM", flags: "g", content: "npm \r publish then publish", expectedLines: [1] },
  { rule: "SHAI_HULUD_WORM", flags: "g", content: "npm+x\rpublish", expectedLines: [1] },
  { rule: "IMPORT_EXPRESSION", flags: "g", content: "import(`one ${a} two ${b}`)", expectedLines: [1] },
  { rule: "IMPORT_EXPRESSION", flags: "g", content: "import( + dynamic)", expectedLines: [1] },
  { rule: "IMPORT_EXPRESSION", flags: "g", content: "import(`plain` + `${value}`)", expectedLines: [] },
  { rule: "STEGANOGRAPHY_DECODE", flags: "g", content: "atob(blob + '.png')", expectedLines: [1] },
  { rule: "STEGANOGRAPHY_DECODE", flags: "g", content: "atob(blob) + '.png'", expectedLines: [] },
  { rule: "SVG_SCRIPT_INJECTION", flags: "g", content: "<script type=x>one</script> tail </script>", expectedLines: [1] },
  { rule: "SVG_SCRIPT_INJECTION", flags: "g", content: "<script </script> x <script>y</script>", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["<script </script> x <script>y</script>"] },
  { rule: "SVG_SCRIPT_INJECTION", flags: "g", content: "button onclick = \"run()\"", expectedLines: [1] },
  { rule: "SVG_SCRIPT_INJECTION", flags: "g", content: "<script>\nrun()\n</script>", expectedLines: [] },
  { rule: "IAC_HARDCODED_SECRET", flags: "g", content: "password = \"s3cure-value-123\"", expectedLines: [1] },
  { rule: "IAC_HARDCODED_SECRET", flags: "g", content: "password = \"stoken=\"abcdefgh\"3cure\"", expectedLines: [1], expectedStarts: [13], expectedEvidence: ["token=\"abcdefgh\""] },
  { rule: "IAC_HARDCODED_SECRET", flags: "g", content: "password = \"${REDIS_PASSWORD}\"", expectedLines: [] },
  { rule: "IAC_HARDCODED_SECRET", flags: "g", content: "password = \"secret_here_123\"", expectedLines: [] },
  { rule: "IAC_HARDCODED_SECRET", flags: "g", content: "password = \"short\"", expectedLines: [] },
  { rule: "DEAD_DROP_DNS_TXT", flags: "g", content: "dig domain.example TXT", expectedLines: [1] },
  { rule: "DEAD_DROP_DNS_TXT", flags: "g", content: "dns.resolveTxt(name)", expectedLines: [1] },
  { rule: "DEAD_DROP_DNS_TXT", flags: "g", content: "resolver.query(name, TXT)", expectedLines: [1] },
  { rule: "DEAD_DROP_DNS_TXT", flags: "g", content: "resolver.query(name, TXTXT)", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["resolver.query(name, TXTXT"] },
  { rule: "DEAD_DROP_DNS_TXT", flags: "g", content: "dig domain\rTXT", expectedLines: [] },
  { rule: "VIDAR_BROWSER_THEFT", flags: "g", content: "AppData/Local/Google/profile/Login Data", expectedLines: [1] },
  { rule: "VIDAR_BROWSER_THEFT", flags: "g", content: "AppData/Local/Google\rLogin Data", expectedLines: [] },
  { rule: "VIDAR_WALLET_THEFT", flags: "g", content: "Exodus profile wallet seed", expectedLines: [1] },
  { rule: "VIDAR_WALLET_THEFT", flags: "g", content: "Trust browser Wallet profile mnemonic", expectedLines: [1] },
  { rule: "VIDAR_WALLET_THEFT", flags: "g", content: "copy wallet.dat", expectedLines: [1] },
  { rule: "DROPPER_ANTIVM", flags: "g", content: "VMware environment detect", expectedLines: [1] },
  { rule: "DROPPER_ANTIVM", flags: "g", content: "IsDebuggerPresent()", expectedLines: [1] },
  { rule: "DROPPER_ANTIVM", flags: "g", content: "VMware\rexit", expectedLines: [] },
  { rule: "README_LURE_URGENCY", flags: "i", content: "DOWNLOAD NOW before it is REMOVED", expectedLines: [1] },
  { rule: "README_LURE_URGENCY", flags: "i", content: "removedownload now x removed", expectedLines: [1], expectedStarts: [6], expectedEvidence: ["download now x removed"] },
  { rule: "README_LURE_URGENCY", flags: "i", content: "download now\rremoved", expectedLines: [] },
  { rule: "CAMPAIGN_CLAUDE_LURE", flags: "i", content: "CLAUDE CODE package is UNLOCKED", expectedLines: [1] },
  { rule: "CAMPAIGN_CLAUDE_LURE", flags: "i", content: "claude code\rfree", expectedLines: [] },
  { rule: "CAMPAIGN_AI_TOOL_LURE", flags: "i", content: "OPENAI SOURCE DUMP", expectedLines: [1] },
  { rule: "CAMPAIGN_AI_TOOL_LURE", flags: "i", content: "openai\rsource dump", expectedLines: [] },
  { rule: "C2_DYNAMIC_CONFIG", flags: "g", content: "fetch('/config').then(eval)", expectedLines: [1] },
  { rule: "C2_DYNAMIC_CONFIG", flags: "g", content: "fetch('/cexeconfig').then(eval)", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["fetch('/cexeconfig').then(eval"] },
  { rule: "C2_DYNAMIC_CONFIG", flags: "g", content: "fetch('/safe') config then eval", expectedLines: [] },
  { rule: "SECRETS_SSH_KEY_READ", flags: "g", content: "readFile('/home/u/.ssh/id_rsa')", expectedLines: [1] },
  { rule: "SECRETS_SSH_KEY_READ", flags: "g", content: "readFile('.ssh/id_rsa.ssh/id_rsa')", expectedLines: [1], expectedStarts: [0], expectedEvidence: ["readFile('.ssh/id_rsa.ssh/id_rsa'"] },
  { rule: "SECRETS_SSH_KEY_READ", flags: "g", content: "readFile\r'/home/u/.ssh/id_rsa'", expectedLines: [] },
  { rule: "CODE_RUNTIME_DEOBFUSCATION", flags: "g", content: "setTimeout(wrapper eval)", expectedLines: [1] },
  { rule: "CODE_RUNTIME_DEOBFUSCATION", flags: "g", content: "setTimeout(wrapper) eval", expectedLines: [] },
];

const nearMissUnits: Readonly<Record<string, string>> = {
  EVAL_HEX: "eval(Buffer.from(payload x ",
  ENV_EXFILTRATION: "process.env.SECRET x ",
  DNS_EXFILTRATION: "dns.resolve x ",
  SCRIPT_NODE_INLINE: "node -e \"safe x ",
  XZ_BUILD_INJECT: "gl_cv_host_cpu_c_abi x ",
  CODECOV_EXFIL: "codecov x ",
  SUNBURST_DELAYED_EXEC: "setTimeout(nope x ",
  UAPARSER_PREINSTALL_DL: "preinstall\": \"safe\" x ",
  MINI_SHAI_HULUD_PREINSTALL: "preinstall\": \"safe\" x ",
  ANTV_WAVE_OTEL_C2: "m-kosche.com/x ",
  COA_RC_POSTINSTALL: "postinstall\":\"safe\" x ",
  PYPI_ENV_EXFILTRATION: "os.environ x ",
  PYPI_HOSTNAME_EXFIL: "socket.gethostname() x ",
  BEACON_INTERVAL_FETCH: "setInterval(nope x ",
  BEACON_TIMEOUT_FETCH: "setTimeout(nope x ",
  PROTESTWARE_LOCALE_DESTRUCT: "timezone x ",
  PROTESTWARE_GEOIP_DESTRUCT: "geoip x ",
  BUILD_PLUGIN_DOWNLOAD: "require(\"plugin\") x ",
  BUILD_ENV_EXFIL: "process.env x ",
  WORKSPACE_ROOT_POSTINSTALL: "\"postinstall\": \"safe\" x ",
  WORKSPACE_PRIVATE_PUBLISH: "\"private\": false x ",
  SHAI_HULUD_WORM: "child_process npm x ",
  IMPORT_EXPRESSION: "import(`plain x ",
  STEGANOGRAPHY_DECODE: "atob(payload x ",
  SVG_SCRIPT_INJECTION: "<script attr x ",
  IAC_HARDCODED_SECRET: "password = \"short\" x ",
  DEAD_DROP_DNS_TXT: "nslookup domain x ",
  VIDAR_BROWSER_THEFT: "AppData/Local/Google/profile x ",
  VIDAR_WALLET_THEFT: "Trust profile x ",
  DROPPER_ANTIVM: "VMware environment x ",
  README_LURE_URGENCY: "download now x ",
  CAMPAIGN_CLAUDE_LURE: "claude code x ",
  CAMPAIGN_AI_TOOL_LURE: "openai x ",
  C2_DYNAMIC_CONFIG: "fetch(config x ",
  SECRETS_SSH_KEY_READ: "readFile .ssh/id_ x ",
  CODE_RUNTIME_DEOBFUSCATION: "setTimeout(nope x ",
};

const caseInsensitiveRules = new Set([
  "SCRIPT_NODE_INLINE",
  "BEACON_INTERVAL_FETCH",
  "BEACON_TIMEOUT_FETCH",
  "PROTESTWARE_LOCALE_DESTRUCT",
  "PROTESTWARE_GEOIP_DESTRUCT",
  "BUILD_PLUGIN_DOWNLOAD",
  "BUILD_ENV_EXFIL",
  "WORKSPACE_ROOT_POSTINSTALL",
  "WORKSPACE_PRIVATE_PUBLISH",
  "README_LURE_URGENCY",
  "CAMPAIGN_CLAUDE_LURE",
  "CAMPAIGN_AI_TOOL_LURE",
]);

describe("core broad-gap structural matchers", () => {
  it.each(parityCases)(
    "$rule preserves legacy start/end/evidence for $content",
    ({ rule, flags, content, expectedLines, expectedStarts, expectedEvidence }) => {
      const structural = shippedRule(rule);
      const baseline = matchPatternInContent(legacyRegexOnly(structural), content, flags);
      const actual = matchPatternInContent(structural, content, flags);
      const baselineStarts = absoluteRegexStarts(content, baseline);

      expect(baseline.map((hit) => hit.line), `${rule} baseline case`).toEqual(expectedLines);
      expect(actual.map((hit) => hit.line), `${rule} lines`).toEqual(expectedLines);
      expect(actual.map((hit) => hit.match.index), `${rule} starts`)
        .toEqual(baselineStarts);
      expect(actual.map((hit) => hit.text), `${rule} evidence`)
        .toEqual(baseline.map((hit) => hit.text));
      if (expectedStarts) {
        expect(baselineStarts, `${rule} exact baseline starts`).toEqual(expectedStarts);
      }
      if (expectedEvidence) {
        expect(baseline.map((hit) => hit.text), `${rule} exact baseline evidence`)
          .toEqual(expectedEvidence);
      }
      expect(actual.coverage.complete, rule).toBe(true);
      expect(actual.coverage.regexAttempts, rule).toBe(1);
    },
  );

  it("keeps exact parity under repeated prefixes, alternatives, and every gap barrier", () => {
    const barriers = [" x ", "\r", "\u2028", ";", "\"", "'", ")", "}", "`", ">"];
    for (const rule of CORE_BROAD_GAP_RULES) {
      const positive = parityCases.find(
        (candidate) => candidate.rule === rule && candidate.expectedLines.length > 0,
      )!;
      const prefix = nearMissUnits[rule]!.slice(0, 64);
      const variants = [
        `${positive.content} tail ${positive.content}`,
        `noise\n${positive.content}`,
        ...barriers.map((barrier) => `${prefix}${barrier}${positive.content}`),
      ];

      for (const content of variants) {
        const structural = shippedRule(rule);
        const baseline = matchPatternInContent(
          legacyRegexOnly(structural),
          content,
          positive.flags,
        );
        const actual = matchPatternInContent(structural, content, positive.flags);
        const label = `${rule}: ${JSON.stringify(content)}`;
        expect(actual.map((hit) => hit.line), `${label} lines`)
          .toEqual(baseline.map((hit) => hit.line));
        expect(actual.map((hit) => hit.match.index), `${label} starts`)
          .toEqual(absoluteRegexStarts(content, baseline));
        expect(actual.map((hit) => hit.text), `${label} evidence`)
          .toEqual(baseline.map((hit) => hit.text));
      }
    }
  });
  it("deliberately hardens Shai-Hulud reverse-order process.env corroboration", () => {
    const rule = shippedRule("SHAI_HULUD_WORM");
    expect(rule.requiresInFile).toBeUndefined();
    expect(rule.requiresInFileMatcher).toBeDefined();
    expect(isPatternApplicableToFile(rule, ".npmrc then child_process", "src/a.js")).toBe(true);
    expect(isPatternApplicableToFile(rule, "execSync first then NPM_TOKEN", "src/a.js")).toBe(true);
    expect(isPatternApplicableToFile(rule, "spawn() first then process.env", "src/a.js")).toBe(true);
    // The old reverse-order regex omitted process.env from its credential arm.
    expect(isPatternApplicableToFile(
      rule,
      "child_process npm publish process.env",
      "src/a.js",
    )).toBe(true);
    expect(isPatternApplicableToFile(rule, ".npmrc only", "src/a.js")).toBe(false);
    expect(isPatternApplicableToFile(rule, "child_process only", "src/a.js")).toBe(false);
  });

  it.each([
    ["PROTESTWARE_LOCALE_DESTRUCT", "locale", "fs.rm(path)"],
    ["PROTESTWARE_GEOIP_DESTRUCT", "geoip", "execSync(cmd)"],
  ] as const)("bounds %s correlation distance without losing a newer local prefix", (rule, prefix, sink) => {
    const pattern = shippedRule(rule);
    const atBoundary = matchPatternInContent(
      pattern,
      `${prefix}${"x".repeat(512)}${sink}`,
      "i",
    );
    expect(atBoundary.map((hit) => hit.line)).toEqual([1]);

    const tooFar = matchPatternInContent(
      pattern,
      `${prefix}${"x".repeat(513)}${sink}`,
      "i",
    );
    expect(tooFar).toEqual([]);
    expect(tooFar.coverage.complete).toBe(true);

    const expiredPrefix = `${prefix}${"x".repeat(513)}`;
    const newerLocalPrefix = matchPatternInContent(
      pattern,
      `${expiredPrefix}${prefix} ${sink}`,
      "i",
    );
    expect(newerLocalPrefix).toHaveLength(1);
    expect(newerLocalPrefix[0]!.match.index).toBe(expiredPrefix.length);
  });

  it.each([
    `const country = profile.country; fs.writeFile("prefs.json", JSON.stringify(profile));`,
    `const timezone = settings.timezone; fs.writeFileSync(cachePath, timezone);`,
  ])("rejects ordinary locale/timezone persistence: %s", (source) => {
    const pattern = shippedRule("PROTESTWARE_LOCALE_DESTRUCT");
    expect(matchPatternInContent(pattern, source, "i")).toEqual([]);
    expect(matchPatternInContent(legacyRegexOnly(pattern), source, "i"))
      .toEqual([]);
  });

  it.each([
    `const locale = currentLocale; fs.rm(cachePath);`,
    `const timezone = settings.timezone; fs.truncate(cachePath, 0, callback);`,
    `const country = profile.country; fs.ftruncate(fd, 0, callback);`,
  ])("retains inherently destructive locale-gated filesystem behavior: %s", (source) => {
    const pattern = shippedRule("PROTESTWARE_LOCALE_DESTRUCT");
    expect(matchPatternInContent(pattern, source, "i")).toHaveLength(1);
    expect(matchPatternInContent(legacyRegexOnly(pattern), source, "i"))
      .toHaveLength(1);
  });
  it("covers every converted matcher on a concrete 5 MiB repeated-prefix near miss", { timeout: 30_000 }, () => {
    expect(Object.keys(nearMissUnits).sort()).toEqual([...CORE_BROAD_GAP_RULES].sort());
    const fiveMiB = 5 * 1024 * 1024;
    const started = performance.now();

    for (const rule of CORE_BROAD_GAP_RULES) {
      const unit = nearMissUnits[rule]!;
      const content = unit.repeat(Math.ceil(fiveMiB / unit.length)).slice(0, fiveMiB);
      const flags = caseInsensitiveRules.has(rule) ? "i" : "g";
      const found = matchPatternInContent(shippedRule(rule), content, flags);
      expect(found, rule).toEqual([]);
      expect(found.coverage.complete, rule).toBe(true);
      expect(found.coverage.regexAttempts, rule).toBe(1);
    }

    const guardOnly = ".npmrc ".repeat(Math.ceil(fiveMiB / 7)).slice(0, fiveMiB);
    expect(shippedRule("SHAI_HULUD_WORM").requiresInFileMatcher!(guardOnly)).toBe(false);
    expect(performance.now() - started).toBeLessThan(performanceBudget(15_000));
  });
});