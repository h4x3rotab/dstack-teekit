import {
  TunnelWebSocketConnect,
  TunnelWebSocketMessage,
  TunnelWebSocketClose,
  TunnelWebSocketEvent,
} from "./types.js"
import { generateConnectionId } from "./utils/client.js"

export class TunnelWebSocket extends EventTarget {
  public readonly CONNECTING = 0
  public readonly OPEN = 1
  public readonly CLOSING = 2
  public readonly CLOSED = 3

  public connectionId: string
  public url: string
  public protocol: string = ""
  public readyState: number = this.CONNECTING
  public bufferedAmount: number = 0
  public extensions: string = ""
  public binaryType: BinaryType = "blob"

  public onopen: ((this: WebSocket, ev: Event) => any) | null = null
  public onclose: ((this: WebSocket, ev: CloseEvent) => any) | null = null
  public onmessage: ((this: WebSocket, ev: MessageEvent) => any) | null = null
  public onerror: ((this: WebSocket, ev: Event) => any) | null = null

  private ra: any
  private messageQueue: string[] = []

  constructor(ra: any, url: string, protocols?: string | string[]) {
    super()
    this.ra = ra
    this.url = url
    this.connectionId = generateConnectionId()

    // Register this connection with the RA instance
    ra.registerWebSocketConnection(this)

    // Send connection request through tunnel
    this.connect(protocols)
  }

  private async connect(protocols?: string | string[]): Promise<void> {
    try {
      await this.ra.ensureConnection()

      const protocolArray = protocols
        ? Array.isArray(protocols)
          ? protocols
          : [protocols]
        : undefined

      const connectMessage: TunnelWebSocketConnect = {
        type: "ws_connect",
        connectionId: this.connectionId,
        url: this.url,
        protocols: protocolArray,
      }

      if (this.ra.ws && this.ra.ws.readyState === WebSocket.OPEN) {
        this.ra.ws.send(JSON.stringify(connectMessage))
      } else {
        throw new Error("Tunnel WebSocket not connected")
      }
    } catch (error) {
      this.handleError(
        error instanceof Error ? error.message : "Connection failed",
      )
    }
  }

  public send(data: string | ArrayBufferLike | Blob | ArrayBufferView): void {
    if (this.readyState === this.CONNECTING) {
      // Queue messages until connection is open
      this.messageQueue.push(String(data))
      return
    }

    if (this.readyState !== this.OPEN) {
      throw new Error("WebSocket is not open")
    }

    const message: TunnelWebSocketMessage = {
      type: "ws_message",
      connectionId: this.connectionId,
      data: String(data), // For now, convert everything to string
      dataType: "string",
    }

    try {
      if (this.ra.ws && this.ra.ws.readyState === WebSocket.OPEN) {
        this.ra.ws.send(JSON.stringify(message))
        this.bufferedAmount += String(data).length
      } else {
        throw new Error("Tunnel WebSocket not connected")
      }
    } catch (error) {
      this.handleError(error instanceof Error ? error.message : "Send failed")
    }
  }

  public close(code?: number, reason?: string): void {
    if (this.readyState === this.CLOSING || this.readyState === this.CLOSED) {
      return
    }

    this.readyState = this.CLOSING

    const closeMessage: TunnelWebSocketClose = {
      type: "ws_close",
      connectionId: this.connectionId,
      code,
      reason,
    }

    try {
      if (this.ra.ws && this.ra.ws.readyState === WebSocket.OPEN) {
        this.ra.ws.send(JSON.stringify(closeMessage))
      }
    } catch (error) {
      console.error("Error sending close message:", error)
    }

    // Clean up
    this.ra.unregisterWebSocketConnection(this.connectionId)
  }

  // Handle events from the tunnel
  public handleTunnelEvent(event: TunnelWebSocketEvent): void {
    switch (event.eventType) {
      case "open":
        this.readyState = this.OPEN
        this.bufferedAmount = 0

        // Send any queued messages
        while (this.messageQueue.length > 0) {
          const queuedData = this.messageQueue.shift()!
          this.send(queuedData)
        }

        const openEvent = new Event("open")
        this.dispatchEvent(openEvent)
        if (this.onopen) {
          this.onopen.call(this as any, openEvent)
        }
        break

      case "close":
        this.readyState = this.CLOSED
        const closeEvent = new CloseEvent("close", {
          code: event.code || 1000,
          reason: event.reason || "",
          wasClean: true,
        })
        this.dispatchEvent(closeEvent)
        if (this.onclose) {
          this.onclose.call(this as any, closeEvent)
        }
        this.ra.unregisterWebSocketConnection(this.connectionId)
        break

      case "error":
        this.handleError(event.error || "WebSocket error")
        break
    }
  }

  public handleTunnelMessage(message: TunnelWebSocketMessage): void {
    if (this.readyState !== this.OPEN) return

    const messageEvent = new MessageEvent("message", {
      data: message.data,
      // TODO: Handle binary data when dataType is 'arraybuffer'
    })

    this.dispatchEvent(messageEvent)
    if (this.onmessage) {
      this.onmessage.call(this as any, messageEvent)
    }
  }

  private handleError(errorMessage: string): void {
    const errorEvent = new Event("error")
    ;(errorEvent as any).message = errorMessage

    this.dispatchEvent(errorEvent)
    if (this.onerror) {
      this.onerror.call(this as any, errorEvent)
    }
  }
}
