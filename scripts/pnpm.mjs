import { existsSync } from "node:fs";
import path from "node:path";

function resolvedPnpmEntryPoint() {
  if (process.env.npm_execpath && existsSync(process.env.npm_execpath)) {
    return process.env.npm_execpath;
  }

  if (process.platform !== "win32") {
    return undefined;
  }

  for (const directory of (process.env.Path ?? process.env.PATH ?? "").split(path.delimiter)) {
    const entryPoint = path.join(directory, "node_modules", "pnpm", "bin", "pnpm.cjs");
    if (existsSync(entryPoint)) {
      return entryPoint;
    }
  }
  return undefined;
}

export function pnpmInvocation(argumentsList) {
  const entryPoint = resolvedPnpmEntryPoint();
  if (entryPoint) {
    return { command: process.execPath, argumentsList: [entryPoint, ...argumentsList] };
  }
  return { command: "pnpm", argumentsList };
}
