import http from "http"
import { WebSocketServer, WebSocket } from "ws"
import { Express } from "express"
import httpMocks from "node-mocks-http"
import { EventEmitter } from "events"
import { TunnelRequest, TunnelResponse } from "./types"
import { parseBody, sanitizeHeaders, getStatusText } from "./utils/server"

export class RA {
  public server: http.Server
  public wss: WebSocketServer
  private app: Express

  constructor(app: Express) {
    this.app = app
    this.server = http.createServer(app)
    this.wss = new WebSocketServer({ server: this.server })

    this.setupTunnelHandler()
  }

  // Intercept WebSocket connections to handle tunnel requests transparently,
  // by overriding the `emit` and `on` handlers.
  private setupTunnelHandler(): void {
    const originalEmit = this.wss.emit.bind(this.wss)

    this.wss.emit = function (event: string, ...args: any[]): boolean {
      if (event === "connection") {
        const ws = args[0] as WebSocket

        const originalOnMessage = ws.on.bind(ws)

        ws.on = function (event: string, listener: any): WebSocket {
          if (event === "message") {
            // Wrap the original listener to handle tunnel requests first
            const wrappedListener = (data: Buffer) => {
              try {
                const message = JSON.parse(data.toString())

                if (message.type === "tunnel_request") {
                  ;(this as any).ra.handleTunnelRequest(
                    ws,
                    message as TunnelRequest,
                  )
                  return
                }
              } catch (error) {
                // If parsing fails, let the original handler deal with it
              }

              // Pass non-tunnel messages to the original listener
              listener(data)
            }

            return originalOnMessage("message", wrappedListener)
          }

          // For non-message events, use original behavior
          return originalOnMessage(event, listener)
        }

        // Store reference to RA instance for tunnel handling
        ;(ws as any).ra = this
      }
      return originalEmit(event, ...args)
    }.bind(this)
  }

  // Handle tunnel requests by synthesizing `fetch` events and passing
  // them to express
  async handleTunnelRequest(
    ws: WebSocket,
    tunnelReq: TunnelRequest,
  ): Promise<void> {
    try {
      // Parse URL to extract pathname and query
      const urlObj = new URL(tunnelReq.url, "http://localhost")
      const query: Record<string, string> = {}
      urlObj.searchParams.forEach((value, key) => {
        query[key] = value
      })

      const req = httpMocks.createRequest({
        method: tunnelReq.method,
        url: tunnelReq.url,
        path: urlObj.pathname,
        headers: tunnelReq.headers,
        body: tunnelReq.body
          ? parseBody(tunnelReq.body, tunnelReq.headers["content-type"])
          : undefined,
        query: query,
      })

      const res = httpMocks.createResponse({
        eventEmitter: EventEmitter,
      })

      // Pass responses back through the tunnel
      res.on("end", () => {
        const response: TunnelResponse = {
          type: "tunnel_response",
          requestId: tunnelReq.requestId,
          status: res.statusCode,
          statusText: res.statusMessage || getStatusText(res.statusCode),
          headers: sanitizeHeaders(res.getHeaders()),
          body: res._getData(),
        }

        ws.send(JSON.stringify(response))
      })

      // Handle errors generically. TODO: better error handling.
      res.on("error", (error) => {
        const errorResponse: TunnelResponse = {
          type: "tunnel_response",
          requestId: tunnelReq.requestId,
          status: 500,
          statusText: "Internal Server Error",
          headers: {},
          body: "",
          error: error.message,
        }

        ws.send(JSON.stringify(errorResponse))
      })

      // Execute the request against the Express app
      this.app(req, res)
    } catch (error) {
      const errorResponse: TunnelResponse = {
        type: "tunnel_response",
        requestId: tunnelReq.requestId,
        status: 500,
        statusText: "Internal Server Error",
        headers: {},
        body: "",
        error: error instanceof Error ? error.message : "Unknown error",
      }

      ws.send(JSON.stringify(errorResponse))
    }
  }

}
