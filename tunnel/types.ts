export type TunnelRequest = {
  type: "tunnel_request"
  requestId: string
  method: string
  url: string
  headers: Record<string, string>
  body?: string
  timeout?: number
}

export type TunnelResponse = {
  type: "tunnel_response"
  requestId: string
  status: number
  statusText: string
  headers: Record<string, string>
  body: string
  error?: string
}

export type TunnelWebSocketConnect = {
  type: "ws_connect"
  connectionId: string
  url: string
  protocols?: string[]
}

export type TunnelWebSocketMessage = {
  type: "ws_message"
  connectionId: string
  data: string
  dataType: "string" | "arraybuffer"
}

export type TunnelWebSocketClose = {
  type: "ws_close"
  connectionId: string
  code?: number
  reason?: string
}

export type TunnelWebSocketEvent = {
  type: "ws_event"
  connectionId: string
  eventType: "open" | "close" | "error"
  code?: number
  reason?: string
  error?: string
}
