const { readFileSync } = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");

function parseToolchainConfig(packageJson, nodeVersion) {
  const pnpmVersion = packageJson.packageManager?.match(/^pnpm@(.+)$/)?.[1];
  const engineNode = packageJson.engines?.node;
  const enginePnpm = packageJson.engines?.pnpm;

  if (!nodeVersion || !pnpmVersion || !engineNode || !enginePnpm) {
    throw new Error("[toolchain] package.json and .node-version must declare Node and pnpm versions.");
  }
  if (nodeVersion !== engineNode || pnpmVersion !== enginePnpm) {
    throw new Error("[toolchain] package.json packageManager/engines and .node-version must agree.");
  }

  return { node: nodeVersion, pnpm: pnpmVersion };
}

function loadToolchainConfig() {
  const packageJson = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const nodeVersion = readFileSync(path.join(root, ".node-version"), "utf8").trim();
  return parseToolchainConfig(packageJson, nodeVersion);
}

module.exports = { loadToolchainConfig, parseToolchainConfig };
