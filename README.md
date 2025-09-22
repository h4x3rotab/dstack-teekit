# ra-https

This repository implements RA-HTTPS and RA-WSS, a set of protocols for
securely connecting to remotely attested Secure Enclaves and Trusted
Execution Environments.

- [x] DCAP quote validation (TDX v4/v5, SGX)
- [x] Encryption (DHKE, X25519 channel)
- [x] HTTPS/WSS tunnel
- [x] HTTPS/WSS demo
- [ ] ServiceWorker
- [ ] Deploy test app to VM

Other todos:

- [x] Works in the browser without polyfills
- [x] Transfer binary data over the wire using CBOR
- [ ] Full test suite for `fetch` requests
- [ ] Full test suite for `WebSocket` usage and emulation
- [ ] Decorators for restricting unencrypted connections

## Demo

Node v22 is expected.

Run the client using `tsx`:

```
npm run dev
```

Run the server using Node.js:

```
npm run server
```

Run the typechecker:

```
npm run typecheck
```

## Deploying

TBD
