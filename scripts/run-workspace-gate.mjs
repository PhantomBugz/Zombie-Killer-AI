import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { pnpmInvocation } from "./pnpm.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const root = process.env.ZK_WORKSPACE_GATE_ROOT ?? repositoryRoot;
const gate = process.argv[2] ?? process.env.ZK_WORKSPACE_GATE;

if (!gate) {
  console.error("Usage: node scripts/run-workspace-gate.mjs <lint|test|typecheck|build>");
  process.exit(1);
}

function workspacePackages() {
  const manifests = [];
  for (const directory of ["apps", "packages"]) {
    const parent = path.join(root, directory);
    if (!existsSync(parent)) {
      continue;
    }
    for (const entry of readdirSync(parent, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      const manifest = path.join(parent, entry.name, "package.json");
      if (existsSync(manifest)) {
        manifests.push({ manifest, relativePath: path.relative(root, path.dirname(manifest)) });
      }
    }
  }
  return manifests;
}

const packages = workspacePackages().map(({ manifest, relativePath }) => ({
  manifest,
  relativePath,
  packageJson: JSON.parse(readFileSync(manifest, "utf8")),
}));

if (packages.length === 0) {
  console.log(`[workspace:${gate}] No JavaScript workspace packages exist yet; baseline gate is complete.`);
  process.exit(0);
}

const rootManifest = path.join(root, "package.json");
if (!existsSync(rootManifest)) {
  console.error(`[workspace:${gate}] ${root} does not contain a root package.json.`);
  process.exit(1);
}
const rootPackage = JSON.parse(readFileSync(rootManifest, "utf8"));
if (!rootPackage.name) {
  console.error(`[workspace:${gate}] Root package.json must declare a name.`);
  process.exit(1);
}

const missing = packages.filter(({ packageJson }) => !packageJson.name || !packageJson.scripts?.[gate]);
if (missing.length > 0) {
  for (const { packageJson, relativePath } of missing) {
    const label = packageJson.name ?? relativePath;
    console.error(`[workspace:${gate}] ${label} does not define a ${gate} script.`);
  }
  process.exit(1);
}

const invocation = pnpmInvocation([
  "-r",
  "--workspace-concurrency=1",
  "--filter",
  `!${rootPackage.name}`,
  "run",
  gate,
]);
const result = spawnSync(invocation.command, invocation.argumentsList, {
  cwd: root,
  stdio: "inherit",
});
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
