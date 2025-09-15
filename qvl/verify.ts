import { createPublicKey, createVerify, X509Certificate } from "node:crypto"
import { getTdxV4SignedRegion, parseTdxQuote } from "./structs.js"
import { encodeEcdsaSignatureToDer, toBase64Url } from "./utils.js"

/**
 * Verify the ECDSA-P256 signature inside a TDX v4 quote against the embedded
 * attestation public key. This checks only the quote signature itself and does
 * not validate the certificate chain or QE report.
 */
export function verifyTdxV4Signature(quoteInput: string | Buffer): boolean {
  const quoteBytes = Buffer.isBuffer(quoteInput)
    ? quoteInput
    : Buffer.from(quoteInput, "base64")

  const { header, signature } = parseTdxQuote(quoteBytes)

  if (header.version !== 4) {
    throw new Error(`Unsupported TDX quote version: ${header.version}`)
  }

  const message = getTdxV4SignedRegion(quoteBytes)

  const rawSig = signature.ecdsa_signature
  const derSig = encodeEcdsaSignatureToDer(rawSig)

  const pub = signature.attestation_public_key
  if (pub.length !== 64) {
    throw new Error("Unexpected attestation public key length")
  }

  const x = toBase64Url(pub.subarray(0, 32))
  const y = toBase64Url(pub.subarray(32, 64))
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x,
    y,
  } as const

  const publicKey = createPublicKey({ key: jwk, format: "jwk" })

  const verifier = createVerify("sha256")
  verifier.update(message)
  verifier.end()
  return verifier.verify(publicKey, derSig)
}

/** Extract PEM certificates embedded in DCAP cert_data (type 5) */
export function extractPemCertificates(certData: Buffer): string[] {
  const text = certData.toString("utf8")
  const pemRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
  const matches = text.match(pemRegex)
  return matches ? matches : []
}

/**
 * Validate a PCK certificate chain embedded in cert_data.
 * - Identifies the leaf certificate and walks up the chain, following issuer/subject chaining.
 * - Expects at least two certificates.
 * - Checks the validity window of each certificate.
 */
export function verifyProvisioningCertificationChain(
  certData: Buffer,
  { verifyAtTimeMs }: { verifyAtTimeMs: number },
): {
  status: "valid" | "invalid" | "expired"
  root: X509Certificate | null
  chain: X509Certificate[]
} {
  const pems = extractPemCertificates(certData)
  if (pems.length === 0) return { status: "invalid", root: null, chain: [] }

  const certs = pems.map((pem) => new X509Certificate(pem))

  // Identify leaf (not an issuer of any other provided cert)
  let leaf: X509Certificate | undefined
  for (const c of certs) {
    const isParentOfAny = certs.some((other) => other.issuer === c.subject)
    if (!isParentOfAny) {
      leaf = c
      break
    }
  }
  if (!leaf) leaf = certs[0]

  // Walk up by issuer -> subject
  const chain: X509Certificate[] = [leaf]
  while (true) {
    const current = chain[chain.length - 1]
    const parent = certs.find((c) => c.subject === current.issuer)
    if (!parent || parent === current) break
    chain.push(parent)
  }

  // Validate chaining and validity windows
  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i]
    const parent = chain[i + 1]
    if (child.issuer !== parent.subject)
      return { status: "invalid", root: null, chain: [] }
  }

  // Check for expired or not-yet-valid certificates
  for (const c of chain) {
    const notBefore = new Date(c.validFrom).getTime()
    const notAfter = new Date(c.validTo).getTime()
    if (!(notBefore <= verifyAtTimeMs && verifyAtTimeMs <= notAfter)) {
      return { status: "expired", root: chain[chain.length - 1] ?? null, chain }
    }
  }

  return { status: "valid", root: chain[chain.length - 1] ?? null, chain }
}

// /** Verify qe_report_signature using PCK leaf certificate public key over qe_report */
// export function verifyQeReportSignature(quoteInput: string | Buffer): boolean {
//   const quoteBytes = Buffer.isBuffer(quoteInput)
//     ? quoteInput
//     : Buffer.from(quoteInput, "base64")

//   const { header, signature } = parseTdxQuote(quoteBytes)
//   if (header.version !== 4) throw new Error("Unsupported quote version")
//   if (!signature.cert_data) throw new Error("Missing cert_data in quote")

//   const pems = extractPemCertificates(signature.cert_data)
//   if (pems.length === 0) throw new Error("No certificates found in cert_data")

//   const derSig = encodeEcdsaSignatureToDer(signature.qe_report_signature)

//   for (const pem of pems) {
//     try {
//       const key = createPublicKey(pem)
//       const verifier = createVerify("sha256")
//       verifier.update(signature.qe_report)
//       verifier.end()
//       if (verifier.verify(key, derSig)) return true
//     } catch {}
//   }
//   return false
// }

// /**
//  * Verify QE binding: qe_report.report_data[0..32) == SHA256(attestation_public_key || qe_auth_data)
//  */
// export function verifyQeReportBinding(quoteInput: string | Buffer): boolean {
//   const quoteBytes = Buffer.isBuffer(quoteInput)
//     ? quoteInput
//     : Buffer.from(quoteInput, "base64")

//   const { header, signature } = parseTdxQuote(quoteBytes)
//   if (header.version !== 4) throw new Error("Unsupported quote version")
//   if (!signature.qe_report_present) throw new Error("Missing QE report")

//   const pubRaw = signature.attestation_public_key
//   const pubUncompressed = Buffer.concat([Buffer.from([0x04]), pubRaw])

//   // Build SPKI DER from JWK and hash that too
//   const jwk = {
//     kty: "EC",
//     crv: "P-256",
//     x: pubRaw.subarray(0, 32).toString("base64url"),
//     y: pubRaw.subarray(32, 64).toString("base64url"),
//   } as const
//   let spki: Buffer | undefined
//   try {
//     spki = createPublicKey({ key: jwk, format: "jwk" }).export({
//       type: "spki",
//       format: "der",
//     }) as Buffer
//   } catch {}

//   const candidates: Buffer[] = []
//   candidates.push(createHash("sha256").update(pubRaw).digest())
//   candidates.push(createHash("sha256").update(pubUncompressed).digest())
//   if (spki) candidates.push(createHash("sha256").update(spki).digest())
//   candidates.push(
//     createHash("sha256").update(pubRaw).update(signature.qe_auth_data).digest(),
//   )
//   candidates.push(
//     createHash("sha256")
//       .update(pubUncompressed)
//       .update(signature.qe_auth_data)
//       .digest(),
//   )

//   // SGX REPORT structure is 384 bytes; report_data occupies the last 64 bytes (offset 320)
//   const reportData = signature.qe_report.subarray(320, 384)
//   const first = reportData.subarray(0, 32)
//   const second = reportData.subarray(32, 64)
//   return candidates.some((c) => c.equals(first) || c.equals(second))
// }
