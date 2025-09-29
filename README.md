# ra-https

This repository implements RA-HTTPS and RA-WSS, a set of protocols for
connecting to Secure Enclaves and Trusted Execution Environments.

## Background

By default, web pages have no way of verifying they are connected to a
TEE, because browsers don't expose certificate information that proves
a connection terminates inside the enclave. This breaks security and
privacy properties of TEEs, since proxies like Cloudflare can
trivially see and modify traffic that goes through them.

To work around this, TEE application hosts typically insert a proxy in
front of the TEE that verifies the connection into the enclave, but this
just moves trust assumptions to the proxy instead.

This repository provides a library that web pages can use to establish a
secure channel into Intel TDX/SGX, that authenticates the TEE and
ensures it's running up-to-date firmware, entirely from within the browser.
This makes it possible to build browser applications that connect to a
verifiable, privacy-preserving backend.

## Components

- ra-https-tunnel: Establishes encrypted channels into TEEs.
  - Encrypted HTTP requests via a `fetch`-compatible API
  - Encrypted WebSockets via a `WebSocket`-compatible API
  - ServiceWorker for upgrading HTTP requests from a browser page
    to use the encrypted channel
- ra-https-qvl: WebCrypto-based SGX/TDX quote verification library
  - Validates the full chain of trust from the root CA, down to report binding
  - Includes embedded CRL/TCB validation that can be used from your browser
- ra-https-demo:
  - A [demo application](https://ra-https.vercel.app/) that supports
    HTTPS and WSS requests over the encrypted channel, both with and without
    the embedded ServiceWorker.

## Usage

On the client, create a `TunnelClient()` object. You should switch out
Node.js `fetch` and `WebSocket` instances for our `fetch` and
`WebSocket` wrappers, exposed on the `TunnelClient()`.

It is your responsibility to configure TunnelClient with the expected
`mrtd` and `report_data` measurements, certificate revocation lists,
and a verifyTcb() function if you wish to check for freshness of the TCB.

Your client will validate these before opening a connection, ensuring
that all traffic terminates inside the trusted execution environment.

```ts
import { TunnelClient } from "ra-https-tunnel"
import { hex, parseTdxQuote } from "ra-https-qvl"

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
    verifyTcb: () => true, // no additional checks for TCB freshness
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
import { TunnelServer } from "ra-https-tunnel"

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
    console.log("ra-https service listening on :3000")
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
`node_modules/ra-https-tunnel/lib/sw.build.js`::

```js
// vite.config.js
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { includeRaServiceWorker } from "ra-https-tunnel/sw"

export default defineConfig({
  plugins: [react(), includeRaServiceWorker()],
})
```

Then, register the ServiceWorker at app startup, pointed at your
tunnel origin:

```ts
// src/main.tsx (or similar)
import { registerServiceWorker } from "ra-https-tunnel/register"

const baseUrl = "http://127.0.0.1:3000" // your TunnelServer origin
registerServiceWorker(baseUrl)
```

Note that different browsers vary in their support of ServiceWorkers.
Some browsers may block ServiceWorkers from being installed. By
default, they intercept link clicks, location.assign() calls,
subresource requests, and fetch() / XMLHttpRequest requests (but not
WebSockets).

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
3. Client verifies the quote (using `ra-https-qvl`), optionally
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
} from "ra-https-tunnel"

class TunnelServer {
  static initialize(
    app: Express,
    getQuote: (x25519PublicKey: Uint8Array) => Promise<Uint8Array> | Uint8Array,
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
      match?: (quote) => boolean;
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
