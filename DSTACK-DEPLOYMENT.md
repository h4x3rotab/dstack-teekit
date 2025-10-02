# Deploying teekit to Phala Cloud (dstack)

This guide explains how to deploy teekit to Phala Cloud, which provides a dstack TEE environment with automatic HTTPS and quote generation.

## Overview

When deployed to Phala Cloud, teekit automatically:
- Fetches TDX quotes from `dstack-guest-agent` via `/var/run/dstack.sock`
- Gets a public HTTPS endpoint with automatic TLS certificates
- Runs inside an Intel TDX Confidential Virtual Machine (CVM)

## Prerequisites

1. Access to Phala Cloud deployment platform
2. Docker and docker-compose installed locally (for testing)
3. Phala Cloud CLI tools (if deploying via CLI)

## Deployment Configuration

### docker-compose.yml

The provided `docker-compose.yml` is configured for Phala Cloud:

```yaml
version: '3.8'

services:
  teekit-demo:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3001:3001"  # Your service port
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock  # dstack-guest-agent socket
    environment:
      - DSTACK_ENABLED=true  # Enable dstack quote provider
      - PORT=3001
```

### Key Configuration Points

1. **Port Mapping**: The `ports` section exposes your service. Phala Cloud automatically generates:
   ```
   https://<app-id>-3001.dstack-prod5.phala.network
   ```

2. **Socket Mount**: The `/var/run/dstack.sock` volume gives access to the dstack-guest-agent for quote generation.

3. **Environment Variables**:
   - `DSTACK_ENABLED=true`: Forces teekit to use dstack's quote provider
   - `PORT=3001`: Sets the server port (must match your port mapping)

## Deployment Steps

### 1. Build and Test Locally

First, ensure your application builds correctly:

```bash
# Install dependencies
npm install

# Build packages
npm run build

# Test the build
docker-compose build
```

### 2. Deploy to Phala Cloud

Follow Phala Cloud's deployment process:

1. Push your code to a Git repository
2. Connect the repository to Phala Cloud
3. Phala Cloud will:
   - Detect the `docker-compose.yml`
   - Build the Docker image inside a TEE
   - Deploy the container to a TDX CVM
   - Provide you with the HTTPS URL

### 3. Access Your Deployment

After deployment, Phala Cloud provides a URL like:
```
https://<app-id>-3001.dstack-prod5.phala.network
```

This URL:
- Has automatic HTTPS with valid TLS certificates
- Terminates inside the `dstack-gateway` TEE
- Routes traffic to your teekit service

## Client Configuration

When connecting to your deployed teekit service, configure the `TunnelClient`:

```typescript
import { TunnelClient } from "@teekit/tunnel"

const origin = "https://<app-id>-3001.dstack-prod5.phala.network"

const client = await TunnelClient.initialize(origin, {
  // Configure expected measurements from your dstack deployment
  mrtd: '<expected-mrtd>',
  report_data: '<expected-report-data>',
  customVerifyQuote: (quote) => {
    // Additional verification logic for dstack quotes
    return true
  }
})

// Use the encrypted tunnel
const response = await client.fetch("/uptime")
console.log(await response.json())
```

## Quote Generation

### How It Works

1. When `TunnelServer` needs a quote, it calls `getQuote(x25519PublicKey)`
2. The server detects it's in a dstack environment (via `isDstackEnvironment()`)
3. It calls `getDstackQuote()` which:
   - Imports `@phala/dstack-sdk`
   - Connects to `/var/run/dstack.sock`
   - Requests a quote with the X25519 public key as `report_data`
   - Returns the TDX quote

### Verification

The TDX quote from dstack includes:
- **MRTD**: Virtual firmware measurement
- **RTMR0**: VM hardware configuration
- **RTMR1**: Linux kernel measurement
- **RTMR2**: Kernel command line + initrd
- **RTMR3**: dstack app details (compose hash, instance ID, app ID)
- **report_data**: Your X25519 public key (32 bytes)

Clients should verify these measurements match expected values for your application.

## Environment-Specific Behavior

teekit automatically adapts to different environments:

| Environment | Quote Provider | Detection Method |
|-------------|---------------|------------------|
| Phala Cloud | dstack-guest-agent | `/var/run/dstack.sock` exists |
| Azure/GCP TDX | Intel Trust Authority CLI | `config.json` exists |
| Development | Sample quote | Neither above exists |

You can force dstack mode with `DSTACK_ENABLED=true`.

## Troubleshooting

### Quote Generation Fails

If you see errors like "Cannot connect to dstack-guest-agent":

1. Verify the socket is mounted:
   ```bash
   docker exec <container> ls -la /var/run/dstack.sock
   ```

2. Check the socket permissions (should be accessible by the container user)

3. Ensure you're running in a dstack CVM, not a regular container

### Port Not Accessible

If the generated URL doesn't work:

1. Verify the port in `docker-compose.yml` matches your server code
2. Check the container logs for startup errors
3. Ensure the health check passes (if configured)

### SDK Import Fails

If `@phala/dstack-sdk` import fails:

1. Verify it's in `package.json` dependencies
2. Run `npm install` in the demo package
3. Rebuild the Docker image

## Advanced Configuration

### Custom Domain

To use a custom domain instead of `*.dstack-prod5.phala.network`:

1. Add a `dstack-ingress` service to your `docker-compose.yml`
2. Configure DNS providers (Cloudflare, etc.)
3. See Phala Cloud networking documentation for details

### Multiple Services

To expose multiple ports:

```yaml
services:
  teekit-demo:
    ports:
      - "3001:3001"  # Main service
      - "8080:8080"  # Additional service
```

Each port gets its own URL:
- `https://<app-id>-3001.dstack-prod5.phala.network`
- `https://<app-id>-8080.dstack-prod5.phala.network`

### gRPC Support

For gRPC services, use the 'g' suffix in the URL:
```
https://<app-id>-8080g.dstack-prod5.phala.network
```

## Production Considerations

1. **Measurement Pinning**: Always pin expected MRTD/RTMR values in your client
2. **Quote Freshness**: Implement TCB verification for production deployments
3. **Error Handling**: Monitor quote generation failures
4. **Rate Limiting**: Consider rate limiting on public endpoints
5. **Logging**: Log quote requests for audit trails

## References

- [Phala Cloud Networking Documentation](https://docs.phala.com/phala-cloud/networking/overview)
- [dstack SDK Documentation](https://github.com/Dstack-TEE/dstack)
- [teekit Architecture](./README.md)
- [Quote Verification](./VERIFICATION.md)
