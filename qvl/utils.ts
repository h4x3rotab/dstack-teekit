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
