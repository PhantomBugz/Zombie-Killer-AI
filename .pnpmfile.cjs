const { readFileSync } = require("node:fs");
const path = require("node:path");
const { loadToolchainConfig } = require("./scripts/toolchain-config.cjs");

const { node: expectedNode, pnpm: expectedPnpm } = loadToolchainConfig();
const requestedBypass = process.env.ZK_ALLOW_UNPINNED_TOOLCHAIN === "1";
const isCi = Boolean(process.env.CI);
const failures = [];

function invokedPnpmVersion() {
  try {
    const manifest = path.join(path.dirname(process.argv[1]), "..", "package.json");
    return JSON.parse(readFileSync(manifest, "utf8")).version;
  } catch {
    return undefined;
  }
}

const actualPnpm = invokedPnpmVersion();

if (requestedBypass && isCi) {
  failures.push("ZK_ALLOW_UNPINNED_TOOLCHAIN is not allowed in CI.");
}

if (process.versions.node !== expectedNode && !requestedBypass) {
  failures.push(`Node ${expectedNode} is required; found ${process.versions.node}.`);
}

if (actualPnpm !== expectedPnpm) {
  failures.push(`pnpm ${expectedPnpm} is required; found ${actualPnpm ?? "unknown"}.`);
}

if (failures.length > 0) {
  throw new Error(
    `[toolchain] ${failures.join(" ")} Controlled local lockfile bootstrap only: set ZK_ALLOW_UNPINNED_TOOLCHAIN=1 for that command. The bypass is rejected in CI and never bypasses pnpm validation.`,
  );
}

module.exports = {
  hooks: {
    readPackage(packageJson) {
      return packageJson;
    },
  },
};
