export type TunnelHTTPRequest = {
  type: "http_request"
  requestId: string
  method: string
  url: string
  headers: Record<string, string>
  body?: string
  timeout?: number
}

export type TunnelHTTPResponse = {
  type: "http_response"
  requestId: string
  status: number
  statusText: string
  headers: Record<string, string>
  body: string
  error?: string
}

// client-sent connect event
export type TunnelWebSocketConnect = {
  type: "ws_connect"
  connectionId: string
  url: string
  protocols?: string[]
}

// client-sent close event
export type TunnelWebSocketClose = {
  type: "ws_close"
  connectionId: string
  code?: number
  reason?: string
}

// client-side and server-side messages
export type TunnelWebSocketMessage = {
  type: "ws_message"
  connectionId: string
  data: string
  dataType: "string" | "arraybuffer"
}

// server-sent events
export type TunnelWebSocketEvent = {
  type: "ws_event"
  connectionId: string
  eventType: "open" | "close" | "error"
  code?: number
  reason?: string
  error?: string
}
