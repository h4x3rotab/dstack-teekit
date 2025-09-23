import react from "@vitejs/plugin-react"
import { nodePolyfills } from "vite-plugin-node-polyfills"
import { defineConfig } from "vite"
import { includeRaServiceWorker } from "ra-https-tunnel/sw"

export default defineConfig({
  plugins: [react(), nodePolyfills(), includeRaServiceWorker()],
})
