import test from "ava"
import express, { Request, Response } from "express"
import type { AddressInfo } from "node:net"
import { WebSocket } from "ws"
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

  app.get("/hello", (_req, res) => res.status(200).send("world"))
  app.get("/ok", (_req, res) => res.status(200).send("ok"))
  app.post("/echo", (req: Request, res: Response) => {
    res.status(200).json({ received: req.body })
  })

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

test.serial("Functionality - GET through tunnel", async (t) => {
  const { tunnelServer, tunnelClient } = await startTunnelApp()

  try {
    const response = await tunnelClient.fetch("/hello")
    t.is(response.status, 200)
    const text = await response.text()
    t.is(text, "world")
  } finally {
    await stopTunnel(tunnelServer, tunnelClient)
  }
})

test.serial("Functionality - POST through tunnel", async (t) => {
  const { tunnelServer, tunnelClient } = await startTunnelApp()

  try {
    const payload = { name: "Ada", answer: 42 }
    const response = await tunnelClient.fetch("/echo", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    })
    t.is(response.status, 200)
    const json = await response.json()
    t.deepEqual(json, { received: payload })
  } finally {
    await stopTunnel(tunnelServer, tunnelClient)
  }
})

test.serial(
  "Functionality - WebSocket lifecycle over tunnel (terminates at server wss)",
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

test.serial(
  "Encryption - Server sends only encrypted envelope messages after handshake",
  async (t) => {
    const { tunnelServer, tunnelClient, origin } = await startTunnelApp()

    // Attach echo handler on server app wss
    tunnelServer.wss.on("connection", (ws) => {
      ws.on("message", (data: any) => ws.send(data))
    })

    try {
      await (tunnelClient as any).ensureConnection()
      const rawWs: any = (tunnelClient as any).ws
      const wireMessages: any[] = []
      const handleWire = (data: any) => {
        try {
          const txt = typeof data === "string" ? data : data.toString()
          const msg = JSON.parse(txt)
          wireMessages.push(msg)
        } catch {}
      }
      if (typeof rawWs.on === "function") {
        rawWs.on("message", handleWire)
      } else if (typeof rawWs.addEventListener === "function") {
        rawWs.addEventListener("message", (evt: any) => handleWire(evt.data))
      }

      // Perform a fetch and a ws roundtrip
      const response = await tunnelClient.fetch("/hello")
      t.is(response.status, 200)
      await response.text()

      const TunnelWS = tunnelClient.WebSocket
      const ws = new TunnelWS(origin.replace(/^http/, "ws"))
      await new Promise<void>((resolve) =>
        ws.addEventListener("open", () => resolve()),
      )
      const echoed = new Promise<string>((resolve) =>
        ws.addEventListener("message", (evt: any) => resolve(String(evt.data))),
      )
      ws.send("ping")
      t.is(await echoed, "ping")
      ws.close(1000, "done")

      // Give wire a brief moment to flush
      await new Promise((r) => setTimeout(r, 100))

      // All observed wire messages (after hooking) must be encrypted envelopes
      const types = wireMessages.map((m) => m?.type)
      t.true(types.length > 0)
      t.true(types.every((tpe) => tpe === "enc"))
    } finally {
      await stopTunnel(tunnelServer, tunnelClient)
    }
  },
)

test.serial(
  "Encryption - Server drops plaintext requests, handles encrypted requests",
  async (t: any) => {
    await sodium.ready
    const app = express()
    app.get("/hello", (_req: Request, res: Response) => {
      res.status(200).send("world")
    })

    const quote = loadQuote({ tdxv4: true })
    const tunnelServer = await TunnelServer.initialize(app, quote)
    await new Promise<void>((resolve) => {
      tunnelServer.server.listen(0, "127.0.0.1", () => resolve())
    })
    const address = tunnelServer.server.address() as AddressInfo
    const wsUrl = `ws://127.0.0.1:${address.port}/__ra__`

    const ws = new WebSocket(wsUrl)
    try {
      // Wait for server_kx
      const serverKx: any = await new Promise((resolve) => {
        ws.once("message", (data) => resolve(JSON.parse(data.toString())))
      })
      t.is(serverKx.type, "server_kx")

      const badPlaintextReq = {
        type: "http_request",
        requestId: "r1",
        method: "GET",
        url: "/hello",
        headers: {},
      }

      // Send plaintext before handshake; server should drop
      ws.send(JSON.stringify(badPlaintextReq))
      const noReplyEarly = await Promise.race([
        new Promise<boolean>((resolve) =>
          ws.once("message", () => resolve(false)),
        ),
        new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 150)),
      ])
      t.true(noReplyEarly)

      // Complete handshake
      const serverPub = sodium.from_base64(
        serverKx.x25519PublicKey,
        sodium.base64_variants.ORIGINAL,
      )
      const symmetricKey = sodium.crypto_secretbox_keygen()
      const sealed = sodium.crypto_box_seal(symmetricKey, serverPub)
      const clientKx = {
        type: "client_kx",
        sealedSymmetricKey: sodium.to_base64(
          sealed,
          sodium.base64_variants.ORIGINAL,
        ),
      }
      ws.send(JSON.stringify(clientKx))

      // Send plaintext after handshake; server should drop
      ws.send(JSON.stringify({ ...badPlaintextReq, requestId: "r2" }))
      const noReplyPost = await Promise.race([
        new Promise<boolean>((resolve) =>
          ws.once("message", () => resolve(false)),
        ),
        new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 150)),
      ])
      t.true(noReplyPost)

      // Send encrypted request
      const httpReq = {
        type: "http_request",
        requestId: "r3",
        method: "GET",
        url: "/hello",
        headers: {},
      }
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
      const plaintext = sodium.from_string(JSON.stringify(httpReq))
      const ciphertext = sodium.crypto_secretbox_easy(
        plaintext,
        nonce,
        symmetricKey,
      )
      const envelope = {
        type: "enc",
        nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
        ciphertext: sodium.to_base64(
          ciphertext,
          sodium.base64_variants.ORIGINAL,
        ),
      }
      ws.send(JSON.stringify(envelope))

      // Expect encrypted http_response
      const encResp: any = await new Promise((resolve) =>
        ws.once("message", (data) => resolve(JSON.parse(data.toString()))),
      )
      t.is(encResp.type, "enc")
      const respNonce = sodium.from_base64(
        encResp.nonce,
        sodium.base64_variants.ORIGINAL,
      )
      const respCipher = sodium.from_base64(
        encResp.ciphertext,
        sodium.base64_variants.ORIGINAL,
      )
      const respPlain = sodium.crypto_secretbox_open_easy(
        respCipher,
        respNonce,
        symmetricKey,
      )
      const resp = JSON.parse(sodium.to_string(respPlain))
      t.is(resp.type, "http_response")
      t.is(resp.requestId, "r3")
      t.is(resp.status, 200)
      t.is(resp.statusText, "OK")
      t.is(resp.body, "world")
    } finally {
      await new Promise<void>((resolve) => {
        ws.close()
        resolve()
      })
      await new Promise<void>((resolve) =>
        tunnelServer.wss.close(() => resolve()),
      )
      await new Promise<void>((resolve) =>
        tunnelServer.server.close(() => resolve()),
      )
    }
  },
)

test.serial(
  "Encryption - Client send fails when symmetric key is missing",
  async (t) => {
    const { tunnelServer, tunnelClient } = await startTunnelApp()
    try {
      // Establish connection so ws is OPEN
      await (tunnelClient as any).ensureConnection()
      // Drop the key to simulate corruption/forgetting
      ;(tunnelClient as any).symmetricKey = undefined

      // fetch should reject because send() requires encryption
      const fetchErr = await t.throwsAsync(async () => {
        await tunnelClient.fetch("/ok")
      })
      t.truthy(fetchErr)

      // Also verify that low-level send rejects when key is missing
      await (tunnelClient as any).ensureConnection()
      ;(tunnelClient as any).symmetricKey = undefined
      const sendErr = t.throws(() =>
        (tunnelClient as any).send({ type: "noop" }),
      )
      t.truthy(sendErr)
    } finally {
      await stopTunnel(tunnelServer, tunnelClient)
    }
  },
)
