#!/usr/bin/env node

/**
 * verify-feed-liveness.mjs - Probe npm registry liveness for threat-feed package IOCs.
 *
 * Usage:
 *   node scripts/verify-feed-liveness.mjs <package-name>
 *   node scripts/verify-feed-liveness.mjs --sample <count>
 */

const args = process.argv.slice(2);
const target = args[0];

if (!target) {
  console.error("Usage: node scripts/verify-feed-liveness.mjs <package-name>");
  process.exit(1);
}

async function probePackage(name) {
  try {
    const res = await fetch(`https://registry.npmjs.org/${name}`, {
      headers: { "User-Agent": "supply-chain-guard-liveness-probe" },
    });
    if (res.status === 404) {
      return { name, status: "unpublished_404", isHolding: false, isLive: false };
    }
    const data = await res.json();
    const versions = Object.keys(data.versions || {});
    const isHolding =
      versions.length === 1 &&
      versions[0] === "0.0.1-security" &&
      data.description === "security holding package";

    return {
      name,
      status: isHolding ? "security_holding_package" : versions.length > 0 ? "live" : "unpublished",
      isHolding,
      isLive: !isHolding && versions.length > 0,
      versions,
      maintainers: data.maintainers?.map((m) => m.name || m) || [],
    };
  } catch (err) {
    return { name, status: "error", error: err.message };
  }
}

probePackage(target).then((result) => {
  console.log(JSON.stringify(result, null, 2));
});
