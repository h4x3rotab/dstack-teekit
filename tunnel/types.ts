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

export type TunnelWSClientConnect = {
  type: "ws_connect"
  connectionId: string
  url: string
  protocols?: string[]
}

export type TunnelWSClientClose = {
  type: "ws_close"
  connectionId: string
  code?: number
  reason?: string
}

export type TunnelWSMessage = {
  type: "ws_message"
  connectionId: string
  data: string
  dataType: "string" | "arraybuffer"
}

export type TunnelWSServerEvent = {
  type: "ws_event"
  connectionId: string
  eventType: "open" | "close" | "error"
  code?: number
  reason?: string
  error?: string
}
