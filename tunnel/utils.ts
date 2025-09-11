export function isTextData(data: Buffer): boolean {
  // Simple heuristic to detect if data is likely text
  // Check for null bytes and high-bit characters
  for (let i = 0; i < Math.min(data.length, 1024); i++) {
    const byte = data[i]
    if (byte === 0 || (byte > 127 && byte < 160)) {
      return false
    }
  }
  return true
}

export function getOriginPort(origin: string): number {
  const u = new URL(origin)
  if (u.port) return Number(u.port)
  return u.protocol === "https:" ? 443 : 80
}
