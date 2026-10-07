#!/usr/bin/env node
// Sign the committed feed.json with Ed25519 and write the detached signature.
//
//   FEED_SIGNING_KEY=<private key PEM> node scripts/sign-feed.mjs [feed.json] [feed.json.sig]
//
// The release job runs this before `gh release create`. Releases are immutable,
// so a signature that does not verify cannot be corrected afterwards. The script
// therefore verifies what it wrote against the PUBLIC key that ships in the
// package (src/feed-signing-key.ts) and exits non-zero on any mismatch, which
// turns a wrong or rotated secret into a red release job before anything is
// published.
//
// Dependency-free on purpose: the release job does not run `npm ci`. The public
// key is read out of the TypeScript source by pattern instead of imported.
//
// `--public-key <file>` replaces the embedded key. It exists for the test suite
// and is not passed by the workflow.

import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

function fail(message) {
  console.error(`sign-feed: ${message}`);
  process.exit(1);
}

const args = process.argv.slice(2);
let publicKeyFile;
const positional = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--public-key") publicKeyFile = args[++i];
  else positional.push(args[i]);
}
const feedPath = positional[0] ?? path.join(here, "..", "feed.json");
const sigPath = positional[1] ?? `${feedPath}.sig`;

function embeddedPublicKeyPem() {
  if (publicKeyFile !== undefined) return fs.readFileSync(publicKeyFile, "utf8");
  const source = fs.readFileSync(path.join(here, "..", "src", "feed-signing-key.ts"), "utf8");
  const match = /-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----/.exec(source);
  if (!match) fail("could not find the embedded public key in src/feed-signing-key.ts");
  return match[0];
}

const privatePem = process.env.FEED_SIGNING_KEY;
if (!privatePem || privatePem.trim() === "") fail("FEED_SIGNING_KEY is not set");

let privateKey;
try {
  privateKey = createPrivateKey(privatePem);
} catch {
  // The message is deliberately generic: node's own error can quote key material.
  fail("FEED_SIGNING_KEY is not a readable private key PEM");
}
if (privateKey.asymmetricKeyType !== "ed25519") fail("FEED_SIGNING_KEY is not an Ed25519 key");

const publicKey = createPublicKey(embeddedPublicKeyPem());
const feed = fs.readFileSync(feedPath);
const signature = sign(null, feed, privateKey);
const line = `${signature.toString("base64")}\n`;
fs.writeFileSync(sigPath, line);

// Verify what is on disk, not what is in memory: read both files back.
const writtenFeed = fs.readFileSync(feedPath);
const writtenSig = Buffer.from(fs.readFileSync(sigPath, "utf8").trim(), "base64");
if (writtenSig.length !== 64 || !verify(null, writtenFeed, publicKey, writtenSig)) {
  fs.rmSync(sigPath, { force: true });
  fail(
    "the signature does not verify against the public key embedded in src/feed-signing-key.ts. " +
      "FEED_SIGNING_KEY is not the private half of that key. Nothing was published.",
  );
}
console.log(`sign-feed: signed ${path.basename(feedPath)} (${feed.length} bytes), signature verified against the embedded key`);
