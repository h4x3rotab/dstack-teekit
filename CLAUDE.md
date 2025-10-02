# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

teekit is a minimal, end-to-end verifiable TEE (Trusted Execution Environment) stack that enables web applications to establish secure, remotely-attested connections to services running in Intel TDX/SGX environments. It solves the problem that browsers cannot natively verify TLS certificates terminate inside a TEE, allowing proxies to intercept traffic.

**Integration Context**: This repository is being integrated with dstack's TEE infrastructure. dstack is an SDK and infrastructure system that simplifies deployment of containerized applications into Intel TDX environments via Docker Compose workflows, with services including `dstack-vmm` (CVM orchestration), `dstack-kms` (key management), `dstack-gateway` (network proxy), and `dstack-guest-agent` (in-VM runtime).

## Core Architecture

### Three Main Packages

1. **@teekit/qvl** (Quote Verification Library)
   - WebCrypto-based SGX/TDX quote verification
   - Validates full chain of trust from Intel root CA to report_data binding
   - Key files:
     - `packages/qvl/src/verifyTdx.ts` - TDX quote verification with PCK chain validation
     - `packages/qvl/src/verifySgx.ts` - SGX quote verification
     - `packages/qvl/src/x509.ts` - Certificate chain validation
     - `packages/qvl/src/tcb.ts` - TCB (Trusted Computing Base) status verification
     - `packages/qvl/src/structs.ts` - Binary quote structure definitions using `restructure`

2. **@teekit/tunnel** (Encrypted Channel)
   - Client (`packages/tunnel/src/client.ts`): Initiates key exchange, verifies quotes, provides fetch/WebSocket APIs
   - Server (`packages/tunnel/src/server.ts`): Generates quotes bound to X25519 keys, decrypts/routes requests
   - ServiceWorker (`packages/tunnel/src/sw.ts`): Optional transparent HTTP upgrade in browsers
   - Encryption: XSalsa20-Poly1305 (libsodium `crypto_secretbox`) after X25519 key exchange

3. **@teekit/demo**
   - Reference implementation showing HTTP and WebSocket over encrypted tunnels
   - `packages/demo/server.ts` - Example TunnelServer with chat backend
   - `packages/demo/src/App.tsx` - React client using TunnelClient

### Attestation Protocol Flow

1. Client opens WebSocket to `ws(s)://<host>/__ra__`
2. Server sends `server_kx` with X25519 public key + TDX/SGX quote
3. Client verifies quote (validates Intel certificate chain, checks MRTD/report_data, optionally validates TCB/CRL)
4. Client generates symmetric key, seals it to server via `client_kx` (libsodium `crypto_box_seal`)
5. All subsequent messages are encrypted envelopes: `{ type: "enc", nonce, ciphertext }`

### Quote Verification Requirements

When verifying quotes, the client must check:
- **MRTD**: Virtual firmware measurement (trust anchor for application code)
- **report_data**: Must contain hash of X25519 public key (with optional binding data)
- **Certificate chain**: Validates to Intel SGX Root CA
- **Optional CRL/TCB**: Certificate revocation and TCB freshness checks

For dstack integration, relevant measurements include:
- **RTMR0**: Virtual hardware configuration (CPU, memory, devices)
- **RTMR1**: Linux kernel measurement
- **RTMR2**: Kernel command line + initrd
- **RTMR3**: dstack app details (compose hash, instance ID, app ID, key provider)

## Build Commands

```bash
# Install dependencies
npm install

# Clean build artifacts
npm run clean

# Build all packages (builds qvl, tunnel, then demo)
npm run build

# Typecheck with watch mode
npm run typecheck

# Lint
npm run lint

# Run all tests (uses ava test runner)
npm test

# Run tests for specific package
npm --workspace packages/qvl run test
npm --workspace packages/tunnel run test
```

## Development Commands

```bash
# Run demo client (Vite dev server on http://localhost:5173)
npm run dev

# Run demo server (Express server on http://localhost:3000)
npm run server

# Run both client and server concurrently
npm start

# Preview production build of demo
npm run preview
```

### Package-Specific Development

```bash
# Watch-build @teekit/tunnel (TypeScript + ServiceWorker bundling)
npm --workspace packages/tunnel run dev

# Watch-build @teekit/qvl (TypeScript only)
npm --workspace packages/qvl run dev
```

## Testing

Tests use AVA test runner with tsx for TypeScript execution:
- `packages/tunnel/test/` - Encryption, fetch, and WebSocket tests
- `packages/qvl/test/` - Quote parsing and verification tests

Run single test file:
```bash
npx ava packages/tunnel/test/encryption.test.ts
```

## Quote Generation (TEE Required)

The demo server supports real TDX attestation via Intel Trust Authority CLI:

1. Setup `config.json` with Trust Authority API key:
```json
{
  "trustauthority_api_url": "https://api.trustauthority.intel.com",
  "trustauthority_api_key": "<your-api-key>"
}
```

2. Server uses `trustauthority-cli evidence --tdx --user-data` to bind X25519 public key
3. If `config.json` missing, server serves sample quote from `packages/demo/shared/samples.ts`

See `ATTESTATION-AZURE.md` and `ATTESTATION-GCP.md` for cloud TDX VM setup.

## Key Files for Integration

### Server-Side Integration
- `packages/tunnel/src/server.ts:26-65` - `getQuote` callback signature for binding keys to quotes
- `packages/tunnel/src/server.ts:84-124` - `TunnelServer.initialize()` API
- `packages/tunnel/src/encryptedOnly.ts` - Express middleware to enforce encrypted requests

### Client-Side Integration
- `packages/tunnel/src/client.ts:38-44` - `TunnelClientConfig` for quote verification
- `packages/tunnel/src/client.ts:97-100` - `TunnelClient.initialize()` with mrtd/report_data validation
- `packages/tunnel/src/types.ts` - Core protocol message types

### Quote Verification
- `packages/qvl/src/verifyTdx.ts:41-180` - `verifyPCKChain()` for Intel certificate validation
- `packages/qvl/src/verifyTdx.ts:208-350` - `verifyTdx()` main verification entrypoint
- `packages/qvl/src/tcb.ts` - TCB status and freshness verification

## Important Constraints

- **Node.js >= 22.0.0** required (specified in package.json engines)
- **One keypair per server** - no key rotation or multi-TEE load balancing yet
- **HTTP bodies buffered** - no streaming for large payloads
- **WebSocket.send()** - Does not accept Blob (use ArrayBuffer/Uint8Array)
- **30 second timeout** for client requests (not configurable)
- **All WebSockets must use tunnel** - mixing encrypted/unencrypted WebSockets not supported

## Phala Cloud / dstack Integration

teekit is fully integrated with Phala Cloud's dstack TEE infrastructure for seamless deployment.

### Quote Provider Architecture

The demo server automatically detects the runtime environment and selects the appropriate quote provider:

1. **Phala Cloud/dstack** (`packages/tunnel/src/dstack-quote.ts`):
   - Uses `@phala/dstack-sdk` v0.5.6
   - Connects to `/var/run/dstack.sock` Unix socket
   - Calls `DstackClient.getQuote()` with X25519 public key
   - Auto-detected via `isDstackEnvironment()` or `DSTACK_ENABLED=true`

2. **Intel Trust Authority CLI** (Azure/GCP TDX):
   - Executes `trustauthority-cli evidence --tdx --user-data`
   - Requires `config.json` with API credentials
   - Used when `config.json` exists

3. **Development Mode**:
   - Serves sample quote from `packages/demo/shared/samples.ts`
   - Used when neither above is available

### Deployment to Phala Cloud

See `DSTACK-DEPLOYMENT.md` for complete deployment guide.

Quick deployment:
```bash
# 1. Build and test locally
npm install && npm run build
docker-compose build

# 2. Deploy to Phala Cloud (via Git repository)
# Phala Cloud auto-detects docker-compose.yml and deploys to TDX CVM

# 3. Access your service
# URL: https://<app-id>-3001.dstack-prod5.phala.network
```

### Key Configuration Files

- `docker-compose.yml`: Defines service, mounts `/var/run/dstack.sock`, exposes port 3001
- `Dockerfile`: Multi-stage build for Node.js 22 with teekit packages
- `packages/demo/server.ts:28-40`: Auto-detection and fallback logic for quote providers

### Network Integration

When deployed to Phala Cloud:
- Port `3001` automatically gets HTTPS URL: `https://<app-id>-3001.dstack-prod5.phala.network`
- No manual TLS certificate setup required
- dstack-gateway handles TLS termination with automatic certificates
- No WireGuard or VPN configuration needed

### Measurement Validation

When connecting to a Phala Cloud deployment, clients should verify:
- **MRTD**: Virtual firmware measurement (OVMF)
- **RTMR0**: VM hardware configuration
- **RTMR1**: Linux kernel measurement
- **RTMR2**: Kernel command line + initrd
- **RTMR3**: dstack app details (compose hash, instance ID, app ID, key provider)
- **report_data**: X25519 public key (32 bytes)

## ServiceWorker (Optional Browser Feature)

To transparently upgrade HTTP requests in browsers:

1. Add Vite plugin to serve ServiceWorker:
```javascript
// vite.config.js
import { includeRaServiceWorker } from "@teekit/tunnel/sw"
export default defineConfig({
  plugins: [includeRaServiceWorker()]
})
```

2. Register at app startup:
```typescript
import { registerServiceWorker } from "@teekit/tunnel/register"
registerServiceWorker("http://127.0.0.1:3000")
```

Note: Browser support varies, may silently fail and downgrade to unencrypted.
