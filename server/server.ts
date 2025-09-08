import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';
import cors from 'cors';

interface Message {
  id: string;
  username: string;
  text: string;
  timestamp: string;
}

interface IncomingChatMessage {
  type: 'chat';
  username: string;
  text: string;
}

interface BacklogMessage {
  type: 'backlog';
  messages: Message[];
}

interface BroadcastMessage {
  type: 'message';
  message: Message;
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(cors());
app.use(express.json());

let messages: Message[] = [];
const MAX_MESSAGES = 30;

wss.on('connection', (ws: WebSocket) => {
  console.log('Client connected');

  // Send message backlog to new client
  const backlogMessage: BacklogMessage = {
    type: 'backlog',
    messages: messages
  };
  ws.send(JSON.stringify(backlogMessage));

  ws.on('message', (data: Buffer) => {
    try {
      const message: IncomingChatMessage = JSON.parse(data.toString());
      
      if (message.type === 'chat') {
        const chatMessage: Message = {
          id: Date.now().toString(),
          username: message.username,
          text: message.text,
          timestamp: new Date().toISOString()
        };

        // Add to message history
        messages.push(chatMessage);
        
        // Keep only last 30 messages
        if (messages.length > MAX_MESSAGES) {
          messages = messages.slice(-MAX_MESSAGES);
        }

        // Broadcast to all connected clients
        const broadcastMessage: BroadcastMessage = {
          type: 'message',
          message: chatMessage
        };

        wss.clients.forEach((client: WebSocket) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(broadcastMessage));
          }
        });
      }
    } catch (error) {
      console.error('Error parsing message:', error);
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
  console.log(`WebSocket server running on http://localhost:${PORT}`);
});