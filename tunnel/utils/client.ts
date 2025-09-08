export function generateRequestId(): string {
  return Date.now().toString() + Math.random().toString(36).substr(2, 9)
}

export function generateConnectionId(): string {
  return 'ws_' + Date.now().toString() + Math.random().toString(36).substr(2, 9)
}