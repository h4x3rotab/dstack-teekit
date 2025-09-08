export class RA {
  origin: string

  constructor(origin: string) {
    this.origin = origin
  }

  get WebSocket() {
    return WebSocket.bind(window)
    // throw new Error("unimplemented")
  }

  get fetch() {
    return fetch.bind(window)
    // throw new Error("unimplemented")
  }
}
