import { useState, useEffect, useRef, FormEvent, ChangeEvent } from "react"
import "./App.css"

interface Message {
  id: string
  username: string
  text: string
  timestamp: string
}

interface WebSocketMessage {
  type: "backlog" | "message"
  messages?: Message[]
  message?: Message
  hiddenCount?: number
}

interface ChatMessage {
  type: "chat"
  username: string
  text: string
}

interface UptimeData {
  uptime: {
    milliseconds: number
    seconds: number
    minutes: number
    hours: number
    formatted: string
  }
}

function generateUsername(): string {
  const randomNum = Math.floor(Math.random() * 1000000)
  return `user${randomNum.toString().padStart(6, "0")}`
}

function getStoredUsername(): string {
  const stored = localStorage.getItem("chat-username")
  if (stored) {
    return stored
  }
  const newUsername = generateUsername()
  localStorage.setItem("chat-username", newUsername)
  return newUsername
}

function App() {
  const [messages, setMessages] = useState<Message[]>([])
  const [newMessage, setNewMessage] = useState<string>("")
  const [username] = useState<string>(getStoredUsername)
  const [connected, setConnected] = useState<boolean>(false)
  const [uptime, setUptime] = useState<string>("")
  const [hiddenMessagesCount, setHiddenMessagesCount] = useState<number>(0)
  const wsRef = useRef<WebSocket | null>(null)
  const messagesEndRef = useRef<HTMLDivElement | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  useEffect(scrollToBottom, [messages])

  useEffect(() => {
    const fetchUptime = async () => {
      try {
        const response = await fetch('http://localhost:3001/uptime')
        const data: UptimeData = await response.json()
        setUptime(data.uptime.formatted)
      } catch (error) {
        console.error('Failed to fetch uptime:', error)
      }
    }

    fetchUptime()
    const interval = setInterval(fetchUptime, 10000) // Update every 10 seconds

    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:3001")
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      console.log("Connected to chat server")
      setTimeout(() => {
        inputRef.current?.focus()
      }, 1)
    }

    ws.onmessage = (event: MessageEvent) => {
      const data: WebSocketMessage = JSON.parse(event.data)

      if (data.type === "backlog") {
        setMessages(data.messages || [])
        setHiddenMessagesCount(data.hiddenCount || 0)
      } else if (data.type === "message" && data.message) {
        setMessages((prev) => [...prev, data.message!])
      }
    }

    ws.onclose = () => {
      setConnected(false)
      console.log("Disconnected from chat server")
    }

    ws.onerror = (error: Event) => {
      console.error("WebSocket error:", error)
      setConnected(false)
    }

    return () => {
      ws.close()
    }
  }, [])

  const sendMessage = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()

    if (
      newMessage.trim() &&
      wsRef.current &&
      wsRef.current.readyState === WebSocket.OPEN
    ) {
      const message: ChatMessage = {
        type: "chat",
        username: username,
        text: newMessage.trim(),
      }
      wsRef.current.send(JSON.stringify(message))
      setNewMessage("")
    }
  }

  const formatTime = (timestamp: string): string => {
    return new Date(timestamp).toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
    })
  }

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    setNewMessage(e.target.value)
  }

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h1>Chat Room</h1>
        <div className="user-info">
          <span className="username">You are: {username}</span>
          <span
            className={`status ${connected ? "connected" : "disconnected"}`}
          >
            {connected ? "🟢 Connected" : "🔴 Disconnected"}
          </span>
        </div>
      </div>

      <div className="messages-container">
        {uptime && (
          <div className="uptime-display">
            Server uptime: {uptime}
          </div>
        )}
        {hiddenMessagesCount > 0 && (
          <div className="hidden-messages-display">
            {hiddenMessagesCount} earlier message{hiddenMessagesCount !== 1 ? 's' : ''}
          </div>
        )}
        {messages.map((message) => (
          <div
            key={message.id}
            className={`message ${message.username === username ? "own-message" : "other-message"}`}
          >
            <div className="message-header">
              <span className="message-username">{message.username}</span>
              <span className="message-time">
                {formatTime(message.timestamp)}
              </span>
            </div>
            <div className="message-text">{message.text}</div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={sendMessage} className="message-form">
        <input
          ref={inputRef}
          type="text"
          value={newMessage}
          onChange={handleInputChange}
          placeholder="Type your message..."
          disabled={!connected}
          className="message-input"
          autoFocus
        />
        <button
          type="submit"
          disabled={!connected || !newMessage.trim()}
          className="send-button"
        >
          Send
        </button>
      </form>
    </div>
  )
}

export default App
