import test from "ava"
import express from "express"
import type { AddressInfo } from "node:net"
import sodium from "libsodium-wrappers"

import { TunnelClient, TunnelServer } from "ra-https-tunnel"
import {
  tappdV4Base64,
  trusteeV5Base64,
  occlumSgxBase64,
} from "./samples/samples.js"
import { base64 } from "@scure/base"
import { hex, parseTdxQuote } from "ra-https-qvl"

// Ensure timers don't keep `npx ava --watch` alive (client sets 30s timeouts)
const originalSetTimeout = setTimeout
;(globalThis as any).setTimeout = ((fn: any, ms?: any, ...args: any[]) => {
  const handle: any = (originalSetTimeout as any)(fn, ms, ...args)
  if (handle && typeof handle.unref === "function") handle.unref()
  return handle
}) as any

export function loadQuote({
  sgx,
  tdxv4,
  tdxv5,
}: {
  sgx?: boolean
  tdxv4?: boolean
  tdxv5?: boolean
}): Uint8Array {
  if (sgx) {
    return base64.decode(occlumSgxBase64)
  } else if (tdxv4) {
    return base64.decode(tappdV4Base64)
  } else if (tdxv5) {
    return base64.decode(trusteeV5Base64)
  } else {
    throw new Error("loadQuote: must provide one of sgx, tdxv4, tdxv5")
  }
}

export async function startTunnelApp() {
  await sodium.ready
  const app = express()

  const quote = loadQuote({ tdxv4: true })
  const tunnelServer = await TunnelServer.initialize(app, quote)

  await new Promise<void>((resolve) => {
    tunnelServer.server.listen(0, "127.0.0.1", () => resolve())
  })
  const address = tunnelServer.server.address() as AddressInfo
  const origin = `http://127.0.0.1:${address.port}`

  const quoteBodyParsed = parseTdxQuote(quote).body
  const tunnelClient = await TunnelClient.initialize(origin, {
    mrtd: hex(quoteBodyParsed.mr_td),
    report_data: hex(quoteBodyParsed.report_data),
  })

  return { tunnelServer, tunnelClient, origin }
}

export async function stopTunnel(
  tunnelServer: TunnelServer,
  tunnelClient: TunnelClient,
) {
  try {
    if (tunnelClient.ws) {
      tunnelClient.ws.onclose = () => {}
      tunnelClient.ws.close()
    }
  } catch {}

  await new Promise<void>((resolve) => {
    tunnelServer.wss.close(() => resolve())
  })
  await new Promise<void>((resolve) => {
    tunnelServer.server.close(() => resolve())
  })
}

test.serial(
  "WebSocket lifecycle over tunnel (terminates at server wss)",
  async (t) => {
    const { tunnelServer, tunnelClient, origin } = await startTunnelApp()

    // Attach an echo handler to the server's built-in WebSocketServer
    tunnelServer.wss.on("connection", (ws) => {
      ws.on("message", (data: any) => ws.send(data))
    })

    try {
      const withTimeout = async <T>(
        p: Promise<T>,
        ms: number,
        label: string,
      ) => {
        let to: any
        const timeout = new Promise<never>((_, reject) => {
          to = setTimeout(() => reject(new Error(`${label} timed out`)), ms)
        })
        try {
          return (await Promise.race([p, timeout])) as T
        } finally {
          clearTimeout(to)
        }
      }

      const TunnelWS = tunnelClient.WebSocket
      const ws = new TunnelWS(origin.replace(/^http/, "ws"))

      t.is(ws.readyState, ws.CONNECTING)

      const opened = withTimeout(
        new Promise<void>((resolve) => {
          ws.addEventListener("open", () => resolve())
        }),
        2000,
        "open",
      )

      const earlyClosed = withTimeout(
        new Promise<void>((resolve) => {
          ws.addEventListener("close", () => resolve())
        }),
        4000,
        "early close",
      )
        .then(() => true)
        .catch(() => false)

      await opened
      t.is(ws.readyState, ws.OPEN)

      const message = withTimeout(
        new Promise<string>((resolve) => {
          ws.addEventListener("message", (evt: any) =>
            resolve(String(evt.data)),
          )
        }),
        2000,
        "message",
      )

      ws.send("ping")
      const echoed = await message
      t.is(echoed, "ping")

      const wasEarlyClosed = await earlyClosed
      if (!wasEarlyClosed) {
        const closeEvent = new Promise<void>((resolve) => {
          ws.addEventListener("close", () => resolve())
        })
        ws.close(1000, "done")
        // Wait up to 2s for close event; if not received, assert CLOSING state
        await Promise.race([
          closeEvent,
          new Promise((resolve) => setTimeout(resolve, 2000)),
        ])
        if (ws.readyState !== ws.CLOSED) {
          t.is(ws.readyState, ws.CLOSING)
        }
      }
    } finally {
      await stopTunnel(tunnelServer, tunnelClient)
    }
  },
)
