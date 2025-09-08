import { useState, useEffect, useRef } from 'react'
import './App.css'

function generateUsername() {
  const randomNum = Math.floor(Math.random() * 1000000);
  return `user${randomNum.toString().padStart(6, '0')}`;
}

function getStoredUsername() {
  const stored = localStorage.getItem('chat-username');
  if (stored) {
    return stored;
  }
  const newUsername = generateUsername();
  localStorage.setItem('chat-username', newUsername);
  return newUsername;
}

function App() {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [username] = useState(getStoredUsername);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(scrollToBottom, [messages]);

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:3001');
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      console.log('Connected to chat server');
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.type === 'backlog') {
        setMessages(data.messages || []);
      } else if (data.type === 'message') {
        setMessages(prev => [...prev, data.message]);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      console.log('Disconnected from chat server');
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setConnected(false);
    };

    return () => {
      ws.close();
    };
  }, []);

  const sendMessage = (e) => {
    e.preventDefault();
    
    if (newMessage.trim() && wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'chat',
        username: username,
        text: newMessage.trim()
      }));
      setNewMessage('');
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h1>Chat Room</h1>
        <div className="user-info">
          <span className="username">You are: {username}</span>
          <span className={`status ${connected ? 'connected' : 'disconnected'}`}>
            {connected ? '🟢 Connected' : '🔴 Disconnected'}
          </span>
        </div>
      </div>
      
      <div className="messages-container">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`message ${message.username === username ? 'own-message' : 'other-message'}`}
          >
            <div className="message-header">
              <span className="message-username">{message.username}</span>
              <span className="message-time">{formatTime(message.timestamp)}</span>
            </div>
            <div className="message-text">{message.text}</div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>
      
      <form onSubmit={sendMessage} className="message-form">
        <input
          type="text"
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
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
  );
}

export default App