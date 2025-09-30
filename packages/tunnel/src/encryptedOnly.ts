import type { Request, RequestHandler } from "express"

// Symbol used to mark requests that arrived via the encrypted tunnel
export const ENCRYPTED_REQUEST = Symbol.for("tee-channels:encrypted_request")

export function isEncryptedRequest(req: Request): boolean {
  try {
    return Boolean(req && (req as any)[ENCRYPTED_REQUEST] === true)
  } catch {
    console.warn(
      "tee-channels: isEncryptedRequest could not read Request object",
    )
    return false
  }
}

export function markRequestAsEncrypted(req: Request): void {
  try {
    ;(req as any)[ENCRYPTED_REQUEST] = true
  } catch {
    console.warn(
      "tee-channels: isEncryptedRequest could not mark Request object",
    )
  }
}

/**
 * Express middleware to require that a request was delivered over the
 * encrypted tunnel. Direct HTTP access will be rejected.
 */
export function encryptedOnly(options?: {
  errorStatus?: number
  errorMessage?: string
}): RequestHandler {
  const errorStatus = options?.errorStatus ?? 403
  const errorMessage = options?.errorMessage ?? "Encrypted channel required"
  return (req, res, next) => {
    if (isEncryptedRequest(req)) {
      return next()
    }
    try {
      res.status(errorStatus).type("text/plain").send(errorMessage)
    } catch {
      // In case headers or response are already sent, end the response
      console.warn(
        "tee-channels: isEncryptedRequest could not send error response",
      )
      try {
        res.end()
      } catch {}
    }
  }
}
