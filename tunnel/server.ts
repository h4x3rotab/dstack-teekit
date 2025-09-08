import http from "http"
import { WebSocketServer, WebSocket } from "ws"
import { Express } from "express"

export class RA {
  public server: http.Server
  public wss: WebSocketServer

  constructor(app: Express) {
    this.server = http.createServer(app)
    this.wss = new WebSocketServer({ server: this.server })
  }
}
