import { base64 as scureBase64 } from "@scure/base"
import {
  parseSgxSignature,
  parseTdxSignature,
  QuoteHeader,
  QuoteHeaderType,
  readUInt16LE,
  readUInt32LE,
  SgxReportBody,
  SgxReportBodyType,
  SgxSignature,
  TdxQuoteBody10Type,
  TdxQuoteBody15Type,
  TdxQuoteBody_1_0,
  TdxQuoteBody_1_5,
  TdxSignature,
} from "./structs.js"

/**
 * Parse a TDX 1.0 or 1.5 quote as header, body, and signature.
 */

export function parseTdxQuote(quote: Uint8Array): {
  header: QuoteHeaderType
  body: TdxQuoteBody10Type | TdxQuoteBody15Type
  signature: TdxSignature
} {
  const header = QuoteHeader.fromBuffer(quote)
  if (header.version === 4) {
    const body = TdxQuoteBody_1_0.fromBuffer(quote.subarray(QuoteHeader.size()))
    const signature = parseTdxSignature(quote)

    return { header, body, signature }
  } else if (header.version === 5) {
    const headerLen = QuoteHeader.size()
    const body_type = readUInt16LE(quote, headerLen)
    const body_size = readUInt32LE(quote, headerLen + 2)

    let body: TdxQuoteBody10Type | TdxQuoteBody15Type
    if (body_type === 1) {
      throw new Error("parseQuote: unexpected body_type = 1")
    } else if (body_type === 2) {
      body = TdxQuoteBody_1_0.fromBuffer(
        quote.subarray(headerLen + 2 + 4, headerLen + 2 + 4 + body_size),
      )
    } else if (body_type === 3) {
      body = TdxQuoteBody_1_5.fromBuffer(
        quote.subarray(headerLen + 2 + 4, headerLen + 2 + 4 + body_size),
      )
    } else {
      throw new Error("parseQuote: unexpected body_type")
    }

    const signature = parseTdxSignature(quote, true)
    return { header, body, signature }
  } else {
    throw new Error(
      "parseQuote: Unsupported quote version, only v4 and v5 supported",
    )
  }
}

export function parseTdxQuoteBase64(quote: string) {
  return parseTdxQuote(scureBase64.decode(quote))
}

/**
 * Parse a TDX 1.0 or 1.5 quote as header, body, and signature.
 */
export function parseSgxQuote(quote: Uint8Array): {
  header: QuoteHeaderType
  body: SgxReportBodyType
  signature: SgxSignature
} {
  const header = QuoteHeader.fromBuffer(quote)
  if (header.version !== 3) {
    throw new Error("parseQuote: Unsupported SGX quote version")
  }

  const body = SgxReportBody.fromBuffer(quote.subarray(QuoteHeader.size()))
  const signature = parseSgxSignature(quote)

  return { header, body, signature }
}

export function parseSgxQuoteBase64(quote: string) {
  return parseSgxQuote(scureBase64.decode(quote))
}
