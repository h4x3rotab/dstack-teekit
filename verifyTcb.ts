type TcbInfo = {
  tcbInfo: {
    id: string
    version: number
    issueDate: string
    nextUpdate: string
    tcbType?: number
    fmspc?: string
    pceId?: string
  }
  signature?: string
}

/** Minimal freshness validation for TCB Info collateral. */
export function verifyTcbInfoFreshness(tcbInfo: TcbInfo, atTimeMs?: number) {
  const now = atTimeMs ?? Date.now()
  const info = tcbInfo.tcbInfo
  const notBefore = Date.parse(info.issueDate)
  const notAfter = Date.parse(info.nextUpdate)
  return notBefore <= now && now <= notAfter
}
