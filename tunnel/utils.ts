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

export function toArrayBuffer(
  data: ArrayBufferLike | Blob | ArrayBufferView,
): ArrayBuffer {
  if (data instanceof ArrayBuffer) {
    return data
  } else if (ArrayBuffer.isView(data)) {
    const arrayBuffer = new ArrayBuffer(data.byteLength)
    const out = new Uint8Array(arrayBuffer)
    const input = new Uint8Array(
      data.buffer as ArrayBufferLike,
      (data as ArrayBufferView).byteOffset,
      (data as ArrayBufferView).byteLength,
    )
    out.set(input)
    return arrayBuffer
  } else {
    throw new Error("Blob data not supported yet")
  }
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return (globalThis as any).btoa(binary)
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = (globalThis as any).atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}
