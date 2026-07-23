import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Wails serves the built assets from ./dist and injects the runtime +
// generated bindings under /wails. The dev server URL is discovered by
// Wails automatically (frontend:dev:serverUrl "auto" in wails.json).
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
