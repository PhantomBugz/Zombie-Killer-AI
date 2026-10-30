import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { pnpmInvocation } from "./pnpm.mjs";

const require = createRequire(import.meta.url);
const { loadToolchainConfig } = require("./toolchain-config.cjs");
const { node: expectedNode, pnpm: expectedPnpm } = loadToolchainConfig();
const requestedBypass = process.env.ZK_ALLOW_UNPINNED_TOOLCHAIN === "1" || process.argv.includes("--allow-unpinned");
const isCi = Boolean(process.env.CI);

function installedPnpmVersion() {
  const invocation = pnpmInvocation(["--version"]);
  return execFileSync(invocation.command, invocation.argumentsList, { encoding: "utf8" }).trim();
}

if (requestedBypass && isCi) {
  console.error("[toolchain] ZK_ALLOW_UNPINNED_TOOLCHAIN is not allowed in CI.");
  process.exit(1);
}

let actualPnpm;
try {
  actualPnpm = installedPnpmVersion();
} catch {
  console.error(`[toolchain] pnpm ${expectedPnpm} is required but could not be executed.`);
  process.exit(1);
}

const failures = [];
if (actualPnpm !== expectedPnpm) {
  failures.push(`pnpm ${expectedPnpm} is required; found ${actualPnpm}.`);
}

if (process.versions.node !== expectedNode) {
  if (requestedBypass) {
    console.warn(
      `[toolchain] controlled-development bypass active: allowing Node ${process.versions.node} for local lockfile bootstrapping; Node ${expectedNode} remains required for CI and normal commands.`,
    );
  } else {
    failures.push(`Node ${expectedNode} is required; found ${process.versions.node}.`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`[toolchain] ${failure}`);
  }
  console.error("[toolchain] Controlled local lockfile bootstrap only: set ZK_ALLOW_UNPINNED_TOOLCHAIN=1 for that command. The bypass is rejected in CI and never bypasses pnpm validation.");
  process.exit(1);
}

console.log(`[toolchain] Node ${process.versions.node}; pnpm ${actualPnpm}`);
