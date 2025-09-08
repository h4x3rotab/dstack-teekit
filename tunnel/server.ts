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

  private setupTunnelHandler(): void {
    this.wss.on("connection", (ws: WebSocket) => {
      console.log("Setting up tunnel handler")

      // Intercept messages before they reach application handlers
      const originalEmit = ws.emit.bind(ws)

      ws.emit = function (event: string, ...args: any[]): boolean {
        if (event === "message") {
          const data = args[0] as Buffer
          try {
            const message = JSON.parse(data.toString())

            if (message.type === "tunnel_request") {
              console.log(
                "Tunnel request received:",
                message.requestId,
                message.url,
              )
              ;(this as any).ra
                .handleTunnelRequest(ws, message as TunnelRequest)
                .catch((error: Error) => {
                  console.error("Error handling tunnel request:", error)

                  // Send 500 error response back to client
                  const errorResponse = {
                    type: "tunnel_response",
                    requestId: message.requestId,
                    status: 500,
                    statusText: "Internal Server Error",
                    headers: {},
                    body: "",
                    error: error.message,
                  }

                  try {
                    ws.send(JSON.stringify(errorResponse))
                  } catch (sendError) {
                    console.error("Failed to send error response:", sendError)
                  }
                })
              return true
            }
          } catch (error) {
            // If parsing fails, fall through to application
          }
        }

        // For non-tunnel messages, use original emit
        return originalEmit(event, ...args)
      }
      ;(ws as any).ra = this
    })
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
      // TODO: if ws.send() fails due to connectivity, the client could
      // get out of sync.

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
