import { describe, expect, it } from "vitest";
import {
  ALL_PATTERN_SETS,
  isPatternApplicableToFile,
  matchPatternInContent,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";

const rule = (): PatternEntry => {
  const found = ALL_PATTERN_SETS
    .flatMap(([, set]) => set)
    .find((candidate) => candidate.rule === "VIDAR_WALLET_THEFT");
  if (!found) throw new Error("VIDAR_WALLET_THEFT is not shipped");
  return found as PatternEntry;
};

/** The scanner runs this set case-sensitively ("g"); check matcher and pattern string. */
function lines(content: string, file = "src/app.ts"): { matcher: number[]; regex: number[] } {
  const entry = rule();
  if (!isPatternApplicableToFile(entry, content, file)) return { matcher: [], regex: [] };
  const regexOnly = { ...entry, correlatedMatcher: undefined };
  return {
    matcher: matchPatternInContent(entry, content, "g").map((hit) => hit.line),
    regex: matchPatternInContent(regexOnly, content, "g").map((hit) => hit.line),
  };
}

describe("VIDAR_WALLET_THEFT matches wallet names, not English words inside others", () => {
  it.each([
    "// a phantom dependency keeps seeding the lockfile",
    "logger.info(`phantom rows are seeding the test database`);",
    'const browser = require("phantomjs"); // keystore is configured elsewhere',
    "// Atomicity guarantees keep the vaulted records consistent",
    "// hyperphantom caches keep the seed values",
    "const exodusMigration = runSeeders(db); // phantomReads off, seedlings on",
  ])("ignores %s", (content) => {
    expect(lines(content)).toEqual({ matcher: [], regex: [] });
  });

  it.each([
    "read_file(Exodus_wallet_path)",
    'find("MetaMask", "vault")',
    "wallet.dat",
    "copy wallet.dat",
    "Exodus profile wallet seed",
    "Trust browser Wallet profile mnemonic",
    'const p = path.join(process.env.APPDATA, "Exodus", "exodus.wallet");',
    'wallets = os.path.join(home, ".electrum", "wallets")',
    'const targets = { phantom: "Local Extension Settings/bfnael", file: "vault" };',
    'grab(`${root}/Atomic/Local Storage/leveldb`, "seed");',
    'const dir = "Coinomi/wallets";',
    'steal(profile + "/metamask/keystore")',
    'const ext = { "TrustWallet": "egjidjbpglichdcondbcbdnbeeppgdph", kind: "mnemonic" };',
  ])("still fires on %s", (content) => {
    expect(lines(content)).toEqual({ matcher: [1], regex: [1] });
  });
});
