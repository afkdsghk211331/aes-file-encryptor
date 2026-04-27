/** Build script: produces ESM (.mjs) + CJS (.cjs) + .d.ts from TypeScript. */
import { readdirSync, renameSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join, basename } from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const distDir = join(__dirname, "dist");

// Clean and recreate dist
rmSync(distDir, { recursive: true, force: true });
mkdirSync(distDir, { recursive: true });

// --- ESM build ---
console.log("[build] Compiling ESM...");
execSync("npx tsc", { cwd: __dirname, stdio: "inherit" });

// Rename .js → .mjs
for (const f of readdirSync(distDir)) {
  if (f.endsWith(".js")) {
    renameSync(join(distDir, f), join(distDir, basename(f, ".js") + ".mjs"));
  }
}

// --- CJS build ---
console.log("[build] Compiling CJS...");
const tmp = join(tmpdir(), "aes-cjs-" + Date.now());
mkdirSync(tmp, { recursive: true });
execSync(`npx tsc --module CommonJS --moduleResolution node --outDir "${tmp}"`, {
  cwd: __dirname,
  stdio: "inherit",
});

for (const f of readdirSync(tmp)) {
  if (f.endsWith(".js")) {
    writeFileSync(
      join(distDir, basename(f, ".js") + ".cjs"),
      readFileSync(join(tmp, f)),
    );
  }
}
rmSync(tmp, { recursive: true, force: true });

console.log("[build] Done.");
for (const f of readdirSync(distDir)) {
  console.log(`  dist/${f}`);
}
