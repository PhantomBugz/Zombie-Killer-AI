import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const { loadToolchainConfig, parseToolchainConfig } = require("./toolchain-config.cjs");
const { node: expectedNode, pnpm: expectedPnpm } = loadToolchainConfig();

const sourcePackage = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
assert.throws(
  () => parseToolchainConfig({ ...sourcePackage, engines: { ...sourcePackage.engines, node: "0.0.0" } }, expectedNode),
  /must agree/,
);

function runNode(script, environment = {}) {
  return spawnSync(process.execPath, [path.join(root, script)], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, ...environment },
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

assert.ok(existsSync(path.join(root, "scripts", "check-toolchain.mjs")), "toolchain guard must exist");
assert.ok(existsSync(path.join(root, "scripts", "run-workspace-gate.mjs")), "workspace gate must exist");

const defaultGuard = runNode("scripts/check-toolchain.mjs", { ZK_ALLOW_UNPINNED_TOOLCHAIN: "" });
if (process.versions.node === expectedNode) {
  assert.equal(defaultGuard.status, 0, combinedOutput(defaultGuard));
} else {
  assert.notEqual(defaultGuard.status, 0, "wrong Node version must fail by default");
  assert.match(combinedOutput(defaultGuard), /Node 24\.18\.0 is required/);
}

const localBypass = runNode("scripts/check-toolchain.mjs", {
  CI: "",
  ZK_ALLOW_UNPINNED_TOOLCHAIN: "1",
});
assert.equal(localBypass.status, 0, combinedOutput(localBypass));
if (process.versions.node === expectedNode) {
  assert.match(combinedOutput(localBypass), /Node 24\.18\.0; pnpm 10\.33\.2/);
} else {
  assert.match(combinedOutput(localBypass), /controlled-development bypass active/);
}
assert.match(combinedOutput(localBypass), new RegExp(`pnpm ${expectedPnpm.replaceAll(".", "\\.")}`));

const ciBypass = runNode("scripts/check-toolchain.mjs", {
  CI: "true",
  ZK_ALLOW_UNPINNED_TOOLCHAIN: "1",
});
assert.notEqual(ciBypass.status, 0, "CI must reject the controlled-development bypass");
assert.match(combinedOutput(ciBypass), /not allowed in CI/);

const workspaceLintGate = runNode("scripts/run-workspace-gate.mjs", { ZK_WORKSPACE_GATE: "lint" });
assert.equal(workspaceLintGate.status, 0, combinedOutput(workspaceLintGate));
assert.match(combinedOutput(workspaceLintGate), /@zombie-killer\/desktop@.* lint/);

const fixtureRoot = mkdtempSync(path.join(tmpdir(), "zombie-killer-workspace-gate-"));
const trace = path.join(fixtureRoot, "build-order.log");
const fixturePackage = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
try {
  mkdirSync(path.join(fixtureRoot, "packages", "core"), { recursive: true });
  mkdirSync(path.join(fixtureRoot, "apps", "consumer"), { recursive: true });
  writeFileSync(path.join(fixtureRoot, "pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n  - 'packages/*'\n", "utf8");
  writeFileSync(
    path.join(fixtureRoot, "package.json"),
    JSON.stringify({
      name: "workspace-gate-fixture",
      version: "0.0.0",
      private: true,
      packageManager: fixturePackage.packageManager,
      engines: fixturePackage.engines,
    }),
    "utf8",
  );
  writeFileSync(
    path.join(fixtureRoot, "packages", "core", "package.json"),
    JSON.stringify({
      name: "@zombie-killer/fixture-core",
      version: "0.0.0",
      scripts: { build: "node -e \"require('node:fs').appendFileSync(process.env.ZK_WORKSPACE_TRACE, 'core\\n')\"" },
    }),
    "utf8",
  );
  writeFileSync(
    path.join(fixtureRoot, "apps", "consumer", "package.json"),
    JSON.stringify({
      name: "@zombie-killer/fixture-consumer",
      version: "0.0.0",
      dependencies: { "@zombie-killer/fixture-core": "workspace:*" },
      scripts: { build: "node -e \"require('node:fs').appendFileSync(process.env.ZK_WORKSPACE_TRACE, 'consumer\\n')\"" },
    }),
    "utf8",
  );

  const topologicalBuild = runNode("scripts/run-workspace-gate.mjs", {
    ZK_WORKSPACE_GATE: "build",
    ZK_WORKSPACE_GATE_ROOT: fixtureRoot,
    ZK_WORKSPACE_TRACE: trace,
  });
  assert.equal(topologicalBuild.status, 0, combinedOutput(topologicalBuild));
  assert.equal(readFileSync(trace, "utf8"), "core\nconsumer\n");

  const missingGate = runNode("scripts/run-workspace-gate.mjs", {
    ZK_WORKSPACE_GATE: "typecheck",
    ZK_WORKSPACE_GATE_ROOT: fixtureRoot,
  });
  assert.notEqual(missingGate.status, 0, "workspace members must define every requested gate");
  assert.match(combinedOutput(missingGate), /does not define a typecheck script/);
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
}
assert.equal(existsSync(fixtureRoot), false, "owned temporary fixture must be removed");
assert.equal(existsSync(path.join(root, "apps", "__workspace-gate-test__")), false, "tests must not create source-tree fixture packages");

const ignored = [
  ".pypirc",
  ".netrc",
  "_netrc",
  ".npmrc",
  ".npmrc.local",
  ".ssh/id_ed25519",
];
for (const candidate of ignored) {
  const result = spawnSync("git", ["check-ignore", "-q", "--", candidate], { cwd: root });
  assert.equal(result.status, 0, `${candidate} must be ignored`);
}

for (const candidate of [".npmrc.example", ".pypirc.example", ".netrc.example", ".ssh/id_ed25519.pub", "output/playwright/.gitkeep"]) {
  const result = spawnSync("git", ["check-ignore", "-q", "--", candidate], { cwd: root });
  assert.notEqual(result.status, 0, `${candidate} must remain trackable`);
}

console.log("PASS: toolchain, workspace gate, and repository credential hygiene checks");
