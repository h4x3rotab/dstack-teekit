import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'http';
import cors from 'cors';

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(cors());
app.use(express.json());

let messages = [];
const MAX_MESSAGES = 30;

wss.on('connection', (ws) => {
  console.log('Client connected');

  // Send message backlog to new client
  ws.send(JSON.stringify({
    type: 'backlog',
    messages: messages
  }));

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data);
      
      if (message.type === 'chat') {
        const chatMessage = {
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
        const broadcastMessage = {
          type: 'message',
          message: chatMessage
        };

        wss.clients.forEach(client => {
          if (client.readyState === ws.OPEN) {
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