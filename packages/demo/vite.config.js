import react from "@vitejs/plugin-react"
import { nodePolyfills } from "vite-plugin-node-polyfills"
import { defineConfig } from "vite"

import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import process from "node:process"

// TODO: Update the path so includeRaServiceWorker() middleware
// can be used outside ra-https-demo, and provide as its own package.
function includeRaServiceWorker() {
  // const fromWorkspace = "node_modules/ra-https-tunnel/lib/sw.build.js"
  const fromPackage = "../../node_modules/ra-https-tunnel/lib/sw.build.js"
  const path = resolve(process.cwd(), fromPackage)
  const outName = "sw.js"
  return {
    name: "serve-ra-https-sw",
    configureServer(server) {
      // Serve the file via a middleware in dev
      server.middlewares.use(`/${outName}`, (_req, res) => {
        res.setHeader("Cache-Control", "no-store")
        res.setHeader("Content-Type", "application/javascript; charset=utf-8")
        res.end(readFileSync(path))
      })
    },
    generateBundle() {
      // Emit the file at the build root unchanged (dist/sw.js)
      this.emitFile({
        type: "asset",
        fileName: outName,
        source: readFileSync(path, "utf-8"),
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), nodePolyfills(), includeRaServiceWorker()],
})
