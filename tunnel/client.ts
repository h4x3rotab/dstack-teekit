import {
  TunnelRequest,
  TunnelResponse,
  TunnelWebSocketEvent,
  TunnelWebSocketMessage,
} from "./types.js"
import { generateRequestId } from "./utils/client.js"
import { TunnelWebSocket } from "./TunnelWebSocket.js"

export class RA {
  origin: string
  private ws: WebSocket | null = null
  private pendingRequests = new Map<
    string,
    { resolve: (response: Response) => void; reject: (error: Error) => void }
  >()
  private webSocketConnections = new Map<string, TunnelWebSocket>()
  private reconnectDelay = 1000
  private connectionPromise: Promise<void> | null = null

  constructor(origin: string) {
    this.origin = origin
  }

  // Wait for a connection on `this.ws`, creating a new WebSocket to
  // replace this.ws if necessary.
  private async ensureConnection(): Promise<void> {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return Promise.resolve()
    }

    if (this.connectionPromise) {
      return this.connectionPromise
    }

    this.connectionPromise = new Promise((resolve, reject) => {
      const wsUrl = this.origin.replace(/^http/, "ws")
      this.ws = new WebSocket(wsUrl)

      this.ws.onopen = () => {
        this.connectionPromise = null
        resolve()
      }

      this.ws.onclose = () => {
        this.connectionPromise = null
        setTimeout(() => {
          this.ensureConnection()
        }, this.reconnectDelay)
      }

      this.ws.onerror = (error) => {
        this.connectionPromise = null
        console.error(error)
        reject(new Error("WebSocket connection failed"))
      }

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data)
          if (message.type === "tunnel_response") {
            this.handleTunnelResponse(message as TunnelResponse)
          } else if (message.type === "ws_event") {
            this.handleWebSocketEvent(message as TunnelWebSocketEvent)
          } else if (message.type === "ws_message") {
            this.handleWebSocketMessage(message as TunnelWebSocketMessage)
          }
        } catch (error) {
          console.error("Error parsing WebSocket message:", error)
        }
      }
    })

    return this.connectionPromise
  }

  private handleTunnelResponse(response: TunnelResponse): void {
    const pending = this.pendingRequests.get(response.requestId)
    if (!pending) return

    this.pendingRequests.delete(response.requestId)

    if (response.error) {
      pending.reject(new Error(response.error))
      return
    }

    const syntheticResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    })

    pending.resolve(syntheticResponse)
  }

  private handleWebSocketEvent(event: TunnelWebSocketEvent): void {
    const connection = this.webSocketConnections.get(event.connectionId)
    if (connection) {
      connection.handleTunnelEvent(event)
    }
  }

  private handleWebSocketMessage(message: TunnelWebSocketMessage): void {
    const connection = this.webSocketConnections.get(message.connectionId)
    if (connection) {
      connection.handleTunnelMessage(message)
    }
  }

  public registerWebSocketConnection(connection: TunnelWebSocket): void {
    this.webSocketConnections.set(connection.connectionId, connection)
  }

  public unregisterWebSocketConnection(connectionId: string): void {
    this.webSocketConnections.delete(connectionId)
  }

  get WebSocket() {
    const self = this
    return class extends TunnelWebSocket {
      constructor(url: string, protocols?: string | string[]) {
        super(self, url, protocols)
      }
    }
  }

  get fetch() {
    return async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      await this.ensureConnection()

      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url
      const method = init?.method || "GET"
      const headers: Record<string, string> = {}

      if (init?.headers) {
        if (init.headers instanceof Headers) {
          init.headers.forEach((value, key) => {
            headers[key] = value
          })
        } else if (Array.isArray(init.headers)) {
          init.headers.forEach(([key, value]) => {
            headers[key] = value
          })
        } else {
          Object.assign(headers, init.headers)
        }
      }

      let body: string | undefined
      if (init?.body) {
        if (typeof init.body === "string") {
          body = init.body
        } else {
          body = JSON.stringify(init.body)
        }
      }

      const requestId = generateRequestId()
      const tunnelRequest: TunnelRequest = {
        type: "tunnel_request",
        requestId,
        method,
        url,
        headers,
        body,
      }

      return new Promise<Response>((resolve, reject) => {
        this.pendingRequests.set(requestId, { resolve, reject })

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify(tunnelRequest))
        } else {
          reject(new Error("WebSocket not connected"))
        }

        // Timeout handling
        setTimeout(() => {
          if (this.pendingRequests.has(requestId)) {
            this.pendingRequests.delete(requestId)
            reject(new Error("Request timeout"))
          }
        }, 30000)
      })
    }
  }
}
