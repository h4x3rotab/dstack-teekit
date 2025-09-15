import { createHash, X509Certificate } from "node:crypto"
import fs from "node:fs"
import path from "node:path"

export const hex = (b: Buffer) => b.toString("hex")

export const reverseHexBytes = (h: string) => {
  return Buffer.from(h, "hex").reverse().toString("hex")
}

/** Convert a raw 64-byte ECDSA signature (r||s) into ASN.1 DER format */
export function encodeEcdsaSignatureToDer(rawSignature: Buffer): Buffer {
  if (rawSignature.length !== 64) {
    throw new Error("Expected 64-byte raw ECDSA signature")
  }

  const r = rawSignature.subarray(0, 32)
  const s = rawSignature.subarray(32, 64)

  const encodeInteger = (buf: Buffer) => {
    let i = 0
    while (i < buf.length && buf[i] === 0x00) i++
    let v = buf.subarray(i)
    if (v.length === 0) v = Buffer.from([0])
    // If high bit is set, prepend 0x00 to indicate positive integer
    if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0x00]), v])
    return Buffer.concat([Buffer.from([0x02, v.length]), v])
  }

  const rEncoded = encodeInteger(r)
  const sEncoded = encodeInteger(s)
  const sequenceLen = rEncoded.length + sEncoded.length
  return Buffer.concat([Buffer.from([0x30, sequenceLen]), rEncoded, sEncoded])
}

export function toBase64Url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
}

/** Extract PEM certificates embedded in DCAP cert_data (type 5) */
export function extractPemCertificates(certData: Buffer): string[] {
  const text = certData.toString("utf8")
  const pemRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
  const matches = text.match(pemRegex)
  return matches ? matches : []
}

/** Compute SHA-256 of a certificate's DER bytes, lowercase hex */
export function computeCertSha256Hex(cert: X509Certificate): string {
  return createHash("sha256").update(cert.raw).digest("hex")
}

/** Load root CA PEMs from local directory. */
export function loadRootCerts(certsDirectory: string): X509Certificate[] {
  const baseDir = path.resolve(certsDirectory)
  let entries: Array<{ name: string; isFile: boolean }>
  try {
    const dirents = fs.readdirSync(baseDir, { withFileTypes: true })
    entries = dirents.map((d) => ({ name: d.name, isFile: d.isFile() }))
  } catch {
    return []
  }

  const results: X509Certificate[] = []
  for (const e of entries) {
    if (!e.isFile) continue
    const lower = e.name.toLowerCase()
    if (
      !lower.endsWith(".pem") &&
      !lower.endsWith(".crt") &&
      !lower.endsWith(".cer")
    )
      continue
    try {
      const filePath = path.join(baseDir, e.name)
      const text = fs.readFileSync(filePath, "utf8")
      const pems = extractPemCertificates(Buffer.from(text, "utf8"))
      for (const pem of pems) {
        try {
          results.push(new X509Certificate(pem))
        } catch {}
      }
    } catch {}
  }
  return results
}
