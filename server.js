import express from "express";
import http from "http";
import { WebSocketServer } from "ws";
import pg from "pg";

const { Pool } = pg;

const app = express();
app.use(express.static("public"));
app.get("/health", (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS channels (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      sender TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS channel_reads (
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      user_name TEXT NOT NULL,
      last_read_message_id BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (channel_id, user_name)
    );
  `);

  // гарантируем general
  await pool.query(
    `INSERT INTO channels (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`,
    ["general"]
  );
}

async function getOrCreateChannel(name) {
  const safe = (name || "general").toLowerCase().trim().slice(0, 40);
  const { rows } = await pool.query(
    `INSERT INTO channels (name) VALUES ($1)
     ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
     RETURNING id, name`,
    [safe || "general"]
  );
  return rows[0];
}

async function listChannels() {
  const { rows } = await pool.query(
    `SELECT id, name FROM channels ORDER BY name ASC LIMIT 200`
  );
  return rows;
}

async function loadHistory(channelId, limit = 200) {
  const { rows } = await pool.query(
    `SELECT id, sender, text, EXTRACT(EPOCH FROM created_at)*1000 AS at
     FROM messages
     WHERE channel_id = $1
     ORDER BY id DESC
     LIMIT $2`,
    [channelId, limit]
  );
  // вернём по возрастанию
  return rows.reverse().map(r => ({
    id: Number(r.id),
    from: r.sender,
    text: r.text,
    at: Number(r.at),
  }));
}

async function saveMessage(channelId, sender, text) {
  const { rows } = await pool.query(
    `INSERT INTO messages (channel_id, sender, text)
     VALUES ($1, $2, $3)
     RETURNING id, EXTRACT(EPOCH FROM created_at)*1000 AS at`,
    [channelId, sender, text]
  );
  return { id: Number(rows[0].id), at: Number(rows[0].at) };
}

function broadcastToChannel(channelName, obj) {
  const payload = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1 && client.channel?.name === channelName) {
      client.send(payload);
    }
  }
}

function broadcastAll(obj) {
  const payload = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(payload);
  }
}

async function broadcastChannels() {
  const chans = await listChannels();
  broadcastAll({ type: "channels", channels: chans.map(c => c.name) });
}

async function setRead(channelId, userName, lastReadId) {
  await pool.query(
    `INSERT INTO channel_reads (channel_id, user_name, last_read_message_id)
     VALUES ($1, $2, $3)
     ON CONFLICT (channel_id, user_name)
     DO UPDATE SET last_read_message_id = GREATEST(channel_reads.last_read_message_id, EXCLUDED.last_read_message_id),
                   updated_at = NOW()`,
    [channelId, userName, lastReadId]
  );
}

async function getReadMin(channelId) {
  // минимальное last_read среди онлайн в этом канале
  const onlineUsers = [];
  for (const c of wss.clients) {
    if (c.readyState === 1 && c.channel?.id === channelId) {
      onlineUsers.push(c.user?.name || "Гость");
    }
  }
  if (onlineUsers.length === 0) return { connected: 0, readUpTo: 0 };

  const { rows } = await pool.query(
    `SELECT MIN(last_read_message_id) AS min_read
     FROM channel_reads
     WHERE channel_id = $1 AND user_name = ANY($2::text[])`,
    [channelId, onlineUsers]
  );

  return {
    connected: onlineUsers.length,
    readUpTo: Number(rows[0]?.min_read || 0),
  };
}

async function broadcastSeen(channel) {
  const { rows } = await pool.query(
    `SELECT COALESCE(MAX(id),0) AS last_id FROM messages WHERE channel_id = $1`,
    [channel.id]
  );
  const lastSeq = Number(rows[0].last_id || 0);
  const { connected, readUpTo } = await getReadMin(channel.id);

  broadcastToChannel(channel.name, {
    type: "seen_state",
    channel: channel.name,
    lastSeq,
    readUpTo,
    connected,
  });
}

wss.on("connection", async (ws) => {
  ws.isAlive = true;
  ws.user = { name: "Гость" };

  // по умолчанию general
  ws.channel = await getOrCreateChannel("general");

  ws.send(JSON.stringify({ type: "channels", channels: (await listChannels()).map(c => c.name) }));
  ws.send(JSON.stringify({ type: "joined", channel: ws.channel.name }));

  const history = await loadHistory(ws.channel.id);
  ws.send(JSON.stringify({ type: "history", channel: ws.channel.name, messages: history }));

  ws.on("pong", () => (ws.isAlive = true));

  ws.on("message", async (buf) => {
    let msg;
    try { msg = JSON.parse(buf.toString("utf8")); } catch { return; }

    if (msg.type === "hello" && typeof msg.name === "string") {
      ws.user.name = msg.name.trim().slice(0, 32) || "Гость";
      await broadcastSeen(ws.channel);
      return;
    }

    if (msg.type === "create_channel" && typeof msg.name === "string") {
      await getOrCreateChannel(msg.name);
      await broadcastChannels();
      return;
    }

    if (msg.type === "join" && typeof msg.channel === "string") {
      ws.channel = await getOrCreateChannel(msg.channel);
      ws.send(JSON.stringify({ type: "joined", channel: ws.channel.name }));
      const history = await loadHistory(ws.channel.id);
      ws.send(JSON.stringify({ type: "history", channel: ws.channel.name, messages: history }));
      await broadcastSeen(ws.channel);
      return;
    }

    if (msg.type === "seen" && typeof msg.seq === "number") {
      const lastRead = Math.max(0, Math.floor(msg.seq));
      await setRead(ws.channel.id, ws.user.name || "Гость", lastRead);
      await broadcastSeen(ws.channel);
      return;
    }

    if (msg.type === "chat" && typeof msg.text === "string") {
      const text = msg.text.trim();
      if (!text) return;

      const saved = await saveMessage(ws.channel.id, ws.user.name || "Гость", text.slice(0, 2000));
      const message = {
        id: saved.id,
        at: saved.at,
        from: ws.user.name || "Гость",
        text: text.slice(0, 2000),
      };

      broadcastToChannel(ws.channel.name, { type: "chat", channel: ws.channel.name, message });
      await broadcastSeen(ws.channel);
      return;
    }
  });

  ws.on("close", async () => {
    // просто обновим read-state для оставшихся
    if (ws.channel) await broadcastSeen(ws.channel);
  });

  await broadcastSeen(ws.channel);
});

// heartbeat
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) ws.terminate();
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);

const PORT = process.env.PORT || 3000;

(async () => {
  await migrate();
  server.listen(PORT, () => console.log(`Listening on :${PORT}`));
})();
