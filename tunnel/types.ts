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