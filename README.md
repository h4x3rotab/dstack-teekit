# ra-https

This repository implements RA-HTTPS and RA-WSS, a set of protocols for
securely connecting to remotely attested Secure Enclaves and Trusted
Execution Environments.

The protocols enforce TDX & SGX quote validation before opening an
encrypted tunnel, ensuring that all traffic over the tunnel terminates
inside the trusted execution environment.

Specifically, we support:

- Encrypted HTTP requests via a `fetch`-compatible client API
- Encrypted WebSockets via a browser-like `WebSocket` client API
- TDX & SGX quote validation before opening an encrypted tunnel

## Usage

On the client, implementing this system requires creating a
`TunnelClient()` object, and switching out Node.js `fetch` and
`WebSocket` instances for a compatible interface.

On the server, implementing the system involves adding a
`TunnelServer` middleware to a Node.js (Express) server. We only
support Express now, but future versions will support arbitrary
backends through Nginx.

```ts
import express from "express"
import { TunnelServer } from "ra-https-tunnel"

async function main() {
  const app = express()
  app.get("/hello", (_req, res) => res.status(200).send("world"))

  const quote: Uint8Array = /* load from your TEE */
  const tunnelServer = await TunnelServer.initialize(app, quote)

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

```ts
import { TunnelClient } from "ra-https-tunnel"
import { hex, parseTdxQuote } from "ra-https-qvl"

async function main() {
  const origin = "http://127.0.0.1:3000"

  // You can validate against expected mrtd/report_data or provide a custom matcher.
  // Below shows fixed values; compute these from an expected quote if you have one.
  const expectedMrtd = /* hex string */
  const expectedReportData = /* hex string */

  const client = await TunnelClient.initialize(origin, {
    mrtd: expectedMrtd,
    report_data: expectedReportData,
    // sgx: true // set if the server quote is SGX; defaults to TDX otherwise
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

Security considerations:

- If you omit `mrtd`, `report_data`, and `match`, the client still
  verifies the quote is valid, but it won’t pin to an expected
  identity.
- One keypair is generated per server process; there’s no session
  resumption across processes. Use sticky sessions if load balancing.

## Limitations

- All WebSocket upgrades to the HTTP server (other than `/__ra__`) are rejected. Application WebSockets must use `tunnelServer.wss`.
- Client WebSocket targets must use the same port as the tunnel `origin`.
- HTTP request bodies supported: string, `Uint8Array`, `ArrayBuffer`, and `ReadableStream`.
- HTTP request/response bodies are buffered end-to-end; very large payloads will increase memory usage.
- Default client request timeout is 30s and not configurable.
- Client `WebSocket.send` does not accept `Blob`.
- Client `fetch` does not natively serialize `FormData`; send a prepared multipart string if needed.
- A single `TunnelClient` reuses one encrypted control channel; each `fetch` is multiplexed over it.
- WebSocket messages queued before `open` are automatically flushed once the socket opens.

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
  static initialize(app: Express, quote: Uint8Array): Promise<TunnelServer>
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
