import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";

/**
 * The public half of the key the release job signs `feed.json` with.
 *
 * The private half exists only as the GitHub Actions repository secret
 * FEED_SIGNING_KEY. A client trusts a feed only when this key verifies its
 * detached Ed25519 signature, so replacing this constant changes who the
 * scanner trusts: feed-signing-key.test.ts pins its fingerprint.
 */
export const FEED_SIGNING_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlOcvVo2r0aHfWegjU/lOpP3t45KE7gXP+hgGgo55spI=
-----END PUBLIC KEY-----
`;

/** First 16 hex digits of the SHA-256 of the key's DER SPKI encoding. */
export const FEED_SIGNING_KEY_FINGERPRINT_PREFIX = "91b2c7d7d50612a3";

/** Beside the feed cache: the exact bytes that were downloaded and signed. */
export const FEED_SIGNED_COPY_FILE = "threat-feed.signed.json";

/** Beside the feed cache: the detached signature over FEED_SIGNED_COPY_FILE. */
export const FEED_SIGNATURE_FILE = "threat-feed.signed.json.sig";

let testKeyOverride: KeyObject | undefined;

/**
 * Replace the trusted key. Test runs only: it is ignored outside vitest, so a
 * program that imports this module cannot swap the trust root, and it is not
 * wired to the CLI, the Action or the MCP server.
 */
export function setFeedPublicKeyForTests(pem: string | undefined): void {
  if (process.env.VITEST === undefined) return;
  testKeyOverride = pem === undefined ? undefined : createPublicKey(pem);
}

function trustedKey(): KeyObject {
  return testKeyOverride ?? createPublicKey(FEED_SIGNING_PUBLIC_KEY_PEM);
}

/** SHA-256 of the key's DER SPKI encoding, lowercase hex. */
export function feedSigningKeyFingerprint(key: KeyObject = createPublicKey(FEED_SIGNING_PUBLIC_KEY_PEM)): string {
  return createHash("sha256")
    .update(key.export({ type: "spki", format: "der" }))
    .digest("hex");
}

/**
 * Check a detached signature over the exact bytes of a feed. Throws with a
 * specific reason; returns normally only for a valid signature.
 *
 * The signature file holds one base64 line. Anything else (empty, wrong
 * alphabet, wrong length) is "malformed" rather than "wrong", so the message
 * says whether the file was damaged or the feed did not match it.
 */
export function assertFeedSignature(data: Buffer, signatureText: string): void {
  const text = signatureText.trim();
  if (text === "") throw new Error("the feed signature is empty");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) throw new Error("the feed signature is not base64");
  const signature = Buffer.from(text, "base64");
  if (signature.length !== 64) {
    throw new Error(`the feed signature is malformed (${signature.length} bytes, an Ed25519 signature has 64)`);
  }
  let ok = false;
  try {
    ok = verify(null, data, trustedKey(), signature);
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new Error(
      "the feed signature does not verify against the signing key bundled with this release " +
        `(fingerprint ${FEED_SIGNING_KEY_FINGERPRINT_PREFIX})`,
    );
  }
}
