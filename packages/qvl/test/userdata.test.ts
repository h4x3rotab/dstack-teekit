import test from "ava"
import fs from "node:fs"
import { base64 as scureBase64 } from "@scure/base"

import { parseTdxQuoteBase64 } from "@teekit/qvl"
import {
  getExpectedReportDataFromUserdata,
  isUserdataBound,
} from "@teekit/qvl/utils"

test.serial("get expected report_data by nonce, iat, userdata", async (t) => {
  const data = JSON.parse(
    fs.readFileSync("test/sampleQuotes/tdx-v4-gcp.json", "utf-8"),
  )
  const quoteB64: string = data.tdx.quote
  const nonce: Uint8Array = scureBase64.decode(data.tdx.verifier_nonce.val)
  const iat: Uint8Array = scureBase64.decode(data.tdx.verifier_nonce.iat)

  const quote = parseTdxQuoteBase64(quoteB64)

  const fakeKey = new Uint8Array(32)
  const expected = await getExpectedReportDataFromUserdata(nonce, iat, fakeKey)
  t.is(expected.length, 64)

  const bound = await isUserdataBound(quote, nonce, iat, fakeKey)
  t.false(bound)
})

test.serial("reject empty nonce, iat, userdata", async (t) => {
  const empty = new Uint8Array()
  const some = new Uint8Array([1])
  const key = new Uint8Array(32)

  await t.throwsAsync(
    async () => await getExpectedReportDataFromUserdata(empty, some, key),
    { message: /missing verifier_nonce.val/i },
  )
  await t.throwsAsync(
    async () => await getExpectedReportDataFromUserdata(some, empty, key),
    { message: /missing verifier_nonce.iat/i },
  )
  await t.throwsAsync(
    async () => await getExpectedReportDataFromUserdata(some, some, empty),
    { message: /missing userdata/i },
  )
})
