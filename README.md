# tee-channels

[![tests](https://github.com/canvasxyz/tee-channels/actions/workflows/ci.yml/badge.svg)](https://github.com/canvasxyz/tee-channels/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/tee-channels-tunnel.svg)](https://www.npmjs.com/package/tee-channels-tunnel)
[![npm](https://img.shields.io/npm/v/tee-channels-tunnel?color=33cd56&logo=npm)](https://www.npmjs.com/package/tee-channels-tunnel)

This repository implements a protocol for remotely-attested HTTPS and
WSS channels, which web pages can use to establish secure connections
terminating inside Intel TDX/SGX enclaves.

## Background

Trusted execution environments make it possible to build private,
verifiable web services, but web pages cannot verify they are
connected to a TEE, because browsers don't expose certificate
information that proves a connection terminates inside the secured
environment. This means proxies like Cloudflare can trivially see and
modify traffic to TEEs forwarded through them, and anyone hosting a
TEE app can insert their own TLS proxies to break confidentiality.

To work around this, some TEE application hosts use their own proxy in
front of the TEE to verify connection integrity, but this requires
users to trust the proxy and makes setting up an application
harder. Or, hosts may use certificate log monitoring, but this only
happens out-of-band and does not protect the connection between the
user and the TEE.

Applications using encrypted TEE channels can just use public
certificate authorities like Let's Encrypt and Cloudflare, while
keeping the guarantee that users are directly connecting to the TEE.

The `tee-channels` package is a building block, intended as part of a
planned larger system for simplifying the deployment of TEE
applications.

## Features

- tee-channels-tunnel:
  - Encrypted HTTP requests via a `fetch`-compatible API
  - Encrypted WebSockets via a `WebSocket`-compatible API
  - ServiceWorker for upgrading HTTP requests from a browser page
    to use the encrypted channel
- tee-channels-qvl:
  - WebCrypto-based SGX/TDX quote verification library
  - Validates the full chain of trust from the root CA, down to binding
    the public key of the encrypted channel in `report_data`
  - Includes CRL/TCB validation that can be (mostly) used from your browser
- tee-channels-demo:
  - A [demo application](https://tee-channels.vercel.app/) that supports
    HTTPS and WSS requests over the encrypted channel, both with and without
    the embedded ServiceWorker.

## Usage

On the client, create a `TunnelClient()` object. You should switch out
unencrypted Node.js `fetch` and `WebSocket` instances for our `fetch` and
`WebSocket` wrappers, exposed on the `TunnelClient()`.

It is your responsibility to configure TunnelClient with the expected
`mrtd` and `report_data` measurements, certificate revocation lists,
verify the TCB manually inside any custom quote validator.

Your client will validate all measurements, quote signatures, and
additional CRL/TCB info before opening a connection.

```ts
import { TunnelClient } from "tee-channels-tunnel"
import { hex, parseTdxQuote } from "tee-channels-qvl"

async function main() {
  const origin = "http://127.0.0.1:3000"

  // You can validate against expected mrtd/report_data or provide a custom matcher.
  // Below shows fixed values; compute these from an expected quote if you have one.
  const expectedMrtd = '...' /* hex string */
  const expectedReportData = '...' /* hex string */

  const client = await TunnelClient.initialize(origin, {
    mrtd: expectedMrtd,
    report_data: expectedReportData,
    crl: [], // certificate revocation list
    verifyTcb: ({ ... }) => true, // check for TCB freshness
    // sgx: true // defaults to TDX otherwise
  })

  // HTTP over tunnel
  const res = await client.fetch("/hello")
  console.log(await res.text()) // server replies "world"

  // WebSocket over tunnel
  const ws = new client.WebSocket(origin.replace(/^http/, "ws"))
  ws.addEventListener("open", () => ws.send("ping"))
  ws.addEventListener("message", (evt: any) => console.log(String(evt.data)))
}

main()
```

On the server, add a `TunnelServer` middleware to your Node.js/Express
server. We only support Node.js now, but future versions will support
arbitrary backends through Nginx.

```ts
import express from "express"
import { TunnelServer } from "tee-channels-tunnel"

async function main() {
  const app = express()
  app.get("/hello", (_req, res) => res.status(200).send("world"))

  async function getQuote(x25519PublicKey: Uint8Array): Promise<Uint8Array> {
    // Return a Uint8Array quote, optionally binding it to x25519PublicKey
    return Uint8Array.fromHex('...')
  }
  const tunnelServer = await TunnelServer.initialize(app, getQuote)

  // Optional: WebSocket support via the built-in mock server
  tunnelServer.wss.on("connection", (ws) => {
    ws.on("message", (data: any) => ws.send(data))
  })

  tunnelServer.server.listen(3000, () => {
    console.log("tee-channels service listening on :3000")
  })
}

main()
```

You may also use the included ServiceWorker to transparently upgrade
HTTP GET/POST requests to go over the encrypted channel to your
`TunnelServer`.

To do this, first add the ServiceWorker plugin to your bundler. You
can use an included Vite plugin to handle this, or manually serve
`__ra-serviceworker__.js` at your web root from
`node_modules/tee-channels-tunnel/lib/sw.build.js`::

```js
// vite.config.js
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { includeRaServiceWorker } from "tee-channels-tunnel/sw"

export default defineConfig({
  plugins: [react(), includeRaServiceWorker()],
})
```

Then, register the ServiceWorker at app startup, pointed at your
tunnel origin:

```ts
// src/main.tsx (or similar)
import { registerServiceWorker } from "tee-channels-tunnel/register"

const baseUrl = "http://127.0.0.1:3000" // your TunnelServer origin
registerServiceWorker(baseUrl)
```

Note that different browsers vary in their support of ServiceWorkers,
and some browsers may block ServiceWorkers from being installed.

By default, ServiceWorkers intercept link clicks, location.assign()
calls, subresource requests, and fetch() / XMLHttpRequest requests
(but not WebSockets).

## Demo

The packages/demo directory contains a demo of a chat app that relays
WebSocket messages and fetch requests over an encrypted channel.

Node v22 is expected.

Run the client using `tsx`:

```
npm run dev
```

Run the server using Node.js:

```
npm run server
```

## Architecture

The tunnel performs a key exchange and attestation check before
allowing any traffic. After the handshake, all payloads are CBOR
encoded and encrypted with the XSalsa20‑Poly1305 stream cipher
(libsodium `crypto_secretbox`).

1. Client opens a control WebSocket to the server at
   `ws(s)://<host>:<port>/__ra__`.
2. Server immediately sends `server_kx` with an X25519 public key and
   a TDX/SGX attestation quote.
3. Client verifies the quote (using `tee-channels-qvl`), optionally
   enforces `mrtd`/`report_data` or a custom matcher, generates a
   symmetric key, and sends it sealed to the server via `client_kx`
   (libsodium `crypto_box_seal`).
4. All subsequent messages are encrypted envelopes
   `{ type: "enc", nonce, ciphertext }` carrying tunneled HTTP
   and WebSocket messages.

## Considerations & Limitations

- For security reasons, we currently require that all WebSocket connections to the HTTP server go through the encrypted channel.
- Client WebSocket targets must use the same port as the tunnel `origin`.
- One keypair is generated per server process. No key rotation (yet) or support for load balancing across TEEs.
- HTTP request bodies supported: string, `Uint8Array`, `ArrayBuffer`, and `ReadableStream`.
- HTTP request/response bodies are buffered end-to-end; very large payloads cannot be streamed.
- The default client request timeout is 30s and not configurable.
- The client `WebSocket.send` does not accept `Blob`.
- The client `fetch` does not natively serialize `FormData`.
- WebSocket messages queued before `open` are automatically flushed once the socket opens.

## API

```ts
import {
  TunnelServer,
  TunnelClient,
  ServerRAMockWebSocket,
  ServerRAMockWebSocketServer,
  ClientRAMockWebSocket,
} from "tee-channels-tunnel"

class TunnelServer {
  static initialize(
    app: Express,
    getQuote: (x25519PublicKey: Uint8Array) => Awaitable<Uint8Array>,
    config?: { heartbeatInterval?: number, heartbeatTimeout?: number }
  ): Promise<TunnelServer>
  server: http.Server                // call `server.listen(...)` to bind a port.
  wss: ServerRAMockWebSocketServer   // emits "connection" and manages `ServerRAMockWebSocket` clients
}

class TunnelClient {
  static initialize(
    origin: string,
    config: {
      mrtd?: string;
      report_data?: string;
      customVerifyQuote?: (quote) => Awaitable<boolean>
      customVerifyX25519Binding?: (client: TunnelClient) => Awaitable<boolean>
      sgx?: boolean
    }
  ): Promise<TunnelClient>

  fetch(input, init?): Promise<Response>   // compatible with Node.js fetch API
  WebSocket: typeof ClientRAMockWebSocket  // compatible with WebSocket constructor
}
```

## Troubleshooting

- Client WebSocket never opens and an `error` event fires immediately:
  - Ensure the target WS URL uses the same port as the client `origin`.
- `Request timeout` after 30 seconds:
  - Server handler may not be responding; confirm your Express route returns a response and that the tunnel server is running.
- Seeing plaintext messages on the wire:
  - Only `server_kx` and `client_kx` are plaintext; everything else must be `{ type: "enc", ... }`.
- `Blob` not supported when sending through WebSocket:
  - Convert to `ArrayBuffer`/`Uint8Array` first.

## License

MIT (C) 2025
