import express from "express";
import http from "http";
import { WebSocketServer } from "ws";

const app = express();
app.use(express.static("public"));

app.get("/health", (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/**
 * Для демо храним последние сообщения в памяти.
 * На хостинге при перезапуске всё обнулится — это нормально для теста.
 */
const lastMessages = [];
const MAX_MESSAGES = 200;

// Простой счётчик “какое сообщение последнее”
let seq = 0;

// Подключения
wss.on("connection", (ws) => {
  ws.isAlive = true;
  ws.user = { name: "Гость" };
  ws.lastSeenSeq = 0;

  // Отдаём историю
  ws.send(JSON.stringify({ type: "history", messages: lastMessages }));

  ws.on("pong", () => (ws.isAlive = true));

  ws.on("message", (buf) => {
    let msg;
    try {
      msg = JSON.parse(buf.toString("utf8"));
    } catch {
      return;
    }

    // Установить имя
    if (msg.type === "hello" && typeof msg.name === "string") {
      ws.user.name = msg.name.slice(0, 32);
      broadcastPresence();
      return;
    }

    // “прочитал до seq”
    if (msg.type === "seen" && typeof msg.seq === "number") {
      ws.lastSeenSeq = Math.max(ws.lastSeenSeq, msg.seq);
      broadcastSeen();
      return;
    }

    // Новое сообщение
    if (msg.type === "chat" && typeof msg.text === "string") {
      const text = msg.text.trim();
      if (!text) return;

      const message = {
        id: ++seq,
        at: Date.now(),
        from: ws.user.name || "Гость",
        text: text.slice(0, 2000)
      };

      lastMessages.push(message);
      if (lastMessages.length > MAX_MESSAGES) lastMessages.shift();

      broadcast({ type: "chat", message });
      broadcastSeen(); // обновим “прочитал” после нового сообщения
    }
  });

  ws.on("close", () => {
    broadcastPresence();
    broadcastSeen();
  });

  broadcastPresence();
  broadcastSeen();
});

function broadcast(obj) {
  const payload = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(payload);
  }
}

function listUsers() {
  const users = [];
  for (const client of wss.clients) {
    if (client.readyState === 1) users.push(client.user?.name || "Гость");
  }
  return users;
}

function broadcastPresence() {
  broadcast({ type: "presence", users: listUsers() });
}

function broadcastSeen() {
  // “минимальный seen” среди всех подключенных = условно “прочитано всеми”
  // Для демо достаточно.
  let minSeen = seq;
  let connected = 0;

  for (const client of wss.clients) {
    if (client.readyState !== 1) continue;
    connected++;
    minSeen = Math.min(minSeen, client.lastSeenSeq || 0);
  }

  broadcast({
    type: "seen_state",
    lastSeq: seq,
    readUpTo: connected > 0 ? minSeen : 0,
    connected
  });
}

// heartbeat, чтобы хостинг не держал “мертвые” соединения
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) ws.terminate();
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
