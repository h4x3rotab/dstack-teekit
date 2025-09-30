import { readFileSync, existsSync } from "node:fs"
import { resolve } from "node:path"
import process from "node:process"
import type express from "express"

export function includeRaServiceWorker() {
  // Look for the serviceworker js bundle
  const fromRoot = "node_modules/tee-channels-tunnel/lib/sw.build.js"
  const fromSubpackage =
    "../../node_modules/tee-channels-tunnel/lib/sw.build.js"

  let path
  if (existsSync(resolve(process.cwd(), fromRoot))) {
    path = resolve(process.cwd(), fromRoot)
  } else if (existsSync(resolve(process.cwd(), fromSubpackage))) {
    path = resolve(process.cwd(), fromSubpackage)
  } else {
    throw new Error(
      "tee-channels-tunnel not found, have you installed the package?",
    )
  }

  const outName = "__ra-serviceworker__.js"
  return {
    name: "serve-ra-serviceworker",
    configureServer(server: any) {
      // Serve the file via a middleware in dev
      server.middlewares.use(
        `/${outName}`,
        (_req: express.Request, res: express.Response) => {
          res.setHeader("Cache-Control", "no-store")
          res.setHeader("Content-Type", "application/javascript; charset=utf-8")
          res.end(readFileSync(path))
        },
      )
    },
    generateBundle() {
      // Emit the file at the build root unchanged (dist/sw.js)
      ;(this as any).emitFile({
        type: "asset",
        fileName: outName,
        source: readFileSync(path, "utf-8"),
      })
    },
  }
}
