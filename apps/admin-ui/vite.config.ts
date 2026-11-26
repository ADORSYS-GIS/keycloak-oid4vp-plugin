import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react-swc";
import { defineConfig, type Plugin } from "vite";
import { checker } from "vite-plugin-checker";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));
const outDir = "dist";

// `AdminConsole` renders `entryImports` from `.vite/manifest.json` verbatim as
// modulepreload links, but Vite stores those entries as manifest keys
// (`_index-….js`) while the emitted file lives at `assets/index-….js`.
// Resolve the keys to real file names, like the backend-integration example in
// the Vite documentation.
function resolveManifestImports(): Plugin {
  return {
    name: "resolve-manifest-imports",
    apply: "build",
    closeBundle() {
      const manifestPath = path.resolve(projectRoot, outDir, ".vite/manifest.json");
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<
        string,
        { file: string; imports?: string[] }
      >;

      for (const chunk of Object.values(manifest)) {
        chunk.imports = chunk.imports?.map((key) => manifest[key]?.file ?? key);
      }

      writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    },
  };
}

// Build for the `keycloak.v2+oid4vp` admin console theme.
//
// This follows `js/apps/admin-ui` in the Keycloak repository:
// - react / react-dom stay external; the theme's index.ftl serves them through
//   an import map from ${resourceCommonUrl}/vendor/react,
// - `manifest: true` emits `.vite/manifest.json`, which the server's
//   `AdminConsole` reads to resolve the entry script/styles/imports,
// - the output lands in `dist`; the Maven build copies it into
//   `theme/keycloak.v2+oid4vp/admin/resources`.
export default defineConfig({
  plugins: [react(), checker({ typescript: true }), resolveManifestImports()],
  base: "",
  build: {
    outDir: outDir,
    emptyOutDir: true,
    sourcemap: true,
    target: "esnext",
    modulePreload: false,
    manifest: true,
    rollupOptions: {
      input: "src/main.tsx",
      external: ["react", "react/jsx-runtime", "react-dom"],
      treeshake: false,
    },
  },
});
