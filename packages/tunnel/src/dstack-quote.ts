import { QuoteData } from "./types.js"
import createDebug from "debug"
import { existsSync } from "node:fs"

const debug = createDebug("teekit:dstack-quote")

/**
 * Get a TDX quote from dstack-guest-agent via the Unix socket at /var/run/dstack.sock
 *
 * This function uses the @phala/dstack-sdk to interact with the dstack-guest-agent
 * running inside a dstack CVM. The quote binds the X25519 public key to the TEE's
 * report_data field.
 *
 * @param x25519PublicKey - The X25519 public key to bind to the quote (max 64 bytes)
 * @returns Promise resolving to QuoteData with the TDX quote
 */
export async function getDstackQuote(
  x25519PublicKey: Uint8Array,
): Promise<QuoteData> {
  try {
    // Dynamically import @phala/dstack-sdk to avoid requiring it in non-dstack environments
    const { DstackClient } = await import("@phala/dstack-sdk")

    debug("Connecting to dstack-guest-agent at /var/run/dstack.sock")
    const client = new DstackClient()

    // The dstack SDK expects report_data to be max 64 bytes
    // Our x25519PublicKey is 32 bytes, which fits within this limit
    if (x25519PublicKey.length > 64) {
      throw new Error(
        `x25519PublicKey too large: ${x25519PublicKey.length} bytes (max 64)`,
      )
    }

    debug(`Getting quote for public key (${x25519PublicKey.length} bytes)`)
    const result = await client.getQuote(x25519PublicKey)

    debug("Quote received from dstack-guest-agent")

    // Convert the hex-encoded quote string to Uint8Array
    const quoteHex = result.quote.startsWith("0x")
      ? result.quote.slice(2)
      : result.quote
    const quoteBytes = hexToBytes(quoteHex)

    // dstack's getQuote returns { quote, event_log, report_data }
    // We only need the quote for teekit's QuoteData format
    return {
      quote: quoteBytes,
      // dstack doesn't use verifier_data or runtime_data in the same way
      // as Intel Trust Authority, so we leave them undefined
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "MODULE_NOT_FOUND") {
      throw new Error(
        "Failed to load @phala/dstack-sdk. Install it with: npm install @phala/dstack-sdk",
      )
    }

    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        "Cannot connect to dstack-guest-agent at /var/run/dstack.sock. " +
        "Ensure you are running inside a dstack CVM with the socket mounted.",
      )
    }

    throw error
  }
}

/**
 * Helper function to convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

/**
 * Check if we're running in a dstack environment by checking for the socket
 */
export function isDstackEnvironment(): boolean {
  try {
    return existsSync("/var/run/dstack.sock")
  } catch {
    return false
  }
}
