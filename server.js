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
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
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

    -- DM
    CREATE TABLE IF NOT EXISTS direct_chats (
      id SERIAL PRIMARY KEY,
      user_a TEXT NOT NULL,
      user_b TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_a, user_b)
    );

    CREATE TABLE IF NOT EXISTS direct_messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id INT NOT NULL REFERENCES direct_chats(id) ON DELETE CASCADE,
      sender TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS direct_reads (
      chat_id INT NOT NULL REFERENCES direct_chats(id) ON DELETE CASCADE,
      user_name TEXT NOT NULL,
      last_read_message_id BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (chat_id, user_name)
    );
  `);

  await pool.query(
    `INSERT INTO channels (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`,
    ["general"]
  );
}

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function broadcastAll(obj) {
  const payload = JSON.stringify(obj);
  for (const c of wss.clients) if (c.readyState === 1) c.send(payload);
}

function broadcastToChannel(channelName, obj) {
  const payload = JSON.stringify(obj);
  for (const c of wss.clients) {
    if (c.readyState === 1 && c.channel?.name === channelName) c.send(payload);
  }
}

// ===== Channels =====
function normalizeChannelName(name) {
  const safe = (name || "general").toLowerCase().trim().slice(0, 40);
  return safe.replace(/\s+/g, "-") || "general";
}

async function getOrCreateChannel(name) {
  const safe = normalizeChannelName(name);
  const { rows } = await pool.query(
    `INSERT INTO channels (name) VALUES ($1)
     ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
     RETURNING id, name`,
    [safe]
  );
  return rows[0];
}

async function listChannels() {
  const { rows } = await pool.query(`SELECT id, name FROM channels ORDER BY name ASC LIMIT 200`);
  return rows;
}

async function loadHistory(channelId, limit = 200) {
  const { rows } = await pool.query(
    `SELECT id, sender, text, EXTRACT(EPOCH FROM created_at)*1000 AS at
     FROM messages WHERE channel_id=$1
     ORDER BY id DESC LIMIT $2`,
    [channelId, limit]
  );
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
     VALUES ($1,$2,$3)
     RETURNING id, EXTRACT(EPOCH FROM created_at)*1000 AS at`,
    [channelId, sender, text]
  );
  return { id: Number(rows[0].id), at: Number(rows[0].at) };
}

async function setChannelRead(channelId, userName, lastReadId) {
  await pool.query(
    `INSERT INTO channel_reads (channel_id, user_name, last_read_message_id)
     VALUES ($1,$2,$3)
     ON CONFLICT (channel_id, user_name)
     DO UPDATE SET last_read_message_id = GREATEST(channel_reads.last_read_message_id, EXCLUDED.last_read_message_id),
                   updated_at=NOW()`,
    [channelId, userName, lastReadId]
  );
}

// ===== Presence (опционально) =====
function listUsersInChannel(channelName) {
  const users = [];
  for (const c of wss.clients) {
    if (c.readyState === 1 && c.channel?.name === channelName) {
      users.push(c.user?.name || "Гость");
    }
  }
  return Array.from(new Set(users.filter(Boolean)));
}

function broadcastPresence(channelName) {
  broadcastToChannel(channelName, { type: "presence", users: listUsersInChannel(channelName) });
}

// ===== Seen state (прочитано всеми онлайн) =====
async function getChannelReadMin(channel) {
  const onlineUsers = listUsersInChannel(channel.name);
  if (!onlineUsers.length) return { connected: 0, readUpTo: 0 };

  const { rows } = await pool.query(
    `SELECT MIN(last_read_message_id) AS min_read
     FROM channel_reads
     WHERE channel_id=$1 AND user_name = ANY($2::text[])`,
    [channel.id, onlineUsers]
  );

  return { connected: onlineUsers.length, readUpTo: Number(rows[0]?.min_read || 0) };
}

async function broadcastSeen(channel) {
  const { rows } = await pool.query(
    `SELECT COALESCE(MAX(id),0) AS last_id FROM messages WHERE channel_id=$1`,
    [channel.id]
  );
  const lastSeq = Number(rows[0].last_id || 0);
  const { connected, readUpTo } = await getChannelReadMin(channel);

  broadcastToChannel(channel.name, {
    type: "seen_state",
    channel: channel.name,
    lastSeq,
    readUpTo,
    connected
  });
}

// ===== Unread badges for channels (per user) =====
async function getChannelsStateForUser(userName) {
  const { rows } = await pool.query(
    `
    SELECT
      c.name,
      COALESCE(m.last_id, 0) AS last_id,
      COALESCE(r.last_read_message_id, 0) AS read_id
    FROM channels c
    LEFT JOIN (
      SELECT channel_id, MAX(id) AS last_id
      FROM messages GROUP BY channel_id
    ) m ON m.channel_id = c.id
    LEFT JOIN channel_reads r
      ON r.channel_id = c.id AND r.user_name = $1
    ORDER BY c.name ASC
    LIMIT 200
    `,
    [userName]
  );

  return rows.map(x => {
    const lastId = Number(x.last_id || 0);
    const readId = Number(x.read_id || 0);
    return { name: x.name, lastId, readId, unread: Math.max(0, lastId - readId) };
  });
}

async function sendChannelsState(ws) {
  const userName = ws.user?.name || "Гость";
  const channels = await getChannelsStateForUser(userName);
  send(ws, { type: "channels_state", channels });
}

async function sendChannelsStateToAll() {
  for (const c of wss.clients) {
    if (c.readyState === 1) sendChannelsState(c).catch(() => {});
  }
}

// ===== DM =====
function normalizeUserPair(a, b) {
  const A = (a || "").trim().slice(0, 32) || "Гость";
  const B = (b || "").trim().slice(0, 32) || "Гость";
  return [A, B].sort((x, y) => x.localeCompare(y));
}

async function getOrCreateDM(user1, user2) {
  const [a, b] = normalizeUserPair(user1, user2);
  const { rows } = await pool.query(
    `INSERT INTO direct_chats (user_a, user_b)
     VALUES ($1,$2)
     ON CONFLICT (user_a, user_b)
     DO UPDATE SET user_a = EXCLUDED.user_a
     RETURNING id, user_a, user_b`,
    [a, b]
  );
  return rows[0];
}

function dmPeer(chat, me) {
  return chat.user_a === me ? chat.user_b : chat.user_a;
}

async function loadDMHistory(chatId, limit = 200) {
  const { rows } = await pool.query(
    `SELECT id, sender, text, EXTRACT(EPOCH FROM created_at)*1000 AS at
     FROM direct_messages
     WHERE chat_id=$1
     ORDER BY id DESC
     LIMIT $2`,
    [chatId, limit]
  );
  return rows.reverse().map(r => ({
    id: Number(r.id),
    from: r.sender,
    text: r.text,
    at: Number(r.at),
  }));
}

async function saveDM(chatId, sender, text) {
  const { rows } = await pool.query(
    `INSERT INTO direct_messages (chat_id, sender, text)
     VALUES ($1,$2,$3)
     RETURNING id, EXTRACT(EPOCH FROM created_at)*1000 AS at`,
    [chatId, sender, text]
  );
  return { id: Number(rows[0].id), at: Number(rows[0].at) };
}

async function setDMRead(chatId, userName, lastReadId) {
  await pool.query(
    `INSERT INTO direct_reads (chat_id, user_name, last_read_message_id)
     VALUES ($1,$2,$3)
     ON CONFLICT (chat_id, user_name)
     DO UPDATE SET last_read_message_id = GREATEST(direct_reads.last_read_message_id, EXCLUDED.last_read_message_id),
                   updated_at=NOW()`,
    [chatId, userName, lastReadId]
  );
}

async function getDMStateForUser(userName) {
  const { rows } = await pool.query(
    `
    SELECT
      dc.id AS chat_id,
      dc.user_a,
      dc.user_b,
      COALESCE(dm.last_id, 0) AS last_id,
      COALESCE(dr.last_read_message_id, 0) AS read_id
    FROM direct_chats dc
    LEFT JOIN (
      SELECT chat_id, MAX(id) AS last_id
      FROM direct_messages
      GROUP BY chat_id
    ) dm ON dm.chat_id = dc.id
    LEFT JOIN direct_reads dr
      ON dr.chat_id = dc.id AND dr.user_name = $1
    WHERE dc.user_a = $1 OR dc.user_b = $1
    ORDER BY GREATEST(COALESCE(dm.last_id,0), dc.id) DESC
    LIMIT 200
    `,
    [userName]
  );

  return rows.map(r => {
    const lastId = Number(r.last_id || 0);
    const readId = Number(r.read_id || 0);
    const peer = (r.user_a === userName) ? r.user_b : r.user_a;
    return { chatId: Number(r.chat_id), peer, lastId, readId, unread: Math.max(0, lastId - readId) };
  });
}

async function sendDMState(ws) {
  const userName = ws.user?.name || "Гость";
  const dms = await getDMStateForUser(userName);
  send(ws, { type: "dms_state", dms });
}

function clientsByName(name) {
  const res = [];
  for (const c of wss.clients) {
    if (c.readyState === 1 && (c.user?.name || "Гость") === name) res.push(c);
  }
  return res;
}

async function sendDMStateToParticipants(a, b) {
  for (const ws of [...clientsByName(a), ...clientsByName(b)]) {
    sendDMState(ws).catch(() => {});
  }
}

// ===== WS =====
wss.on("connection", async (ws) => {
  ws.isAlive = true;
  ws.user = { name: "Гость" };
  ws.channel = await getOrCreateChannel("general");
  ws.mode = "channel";     // 'channel' | 'dm'
  ws.dm = null;            // {chatId, peer}

  // initial
  send(ws, { type: "channels", channels: (await listChannels()).map(c => c.name) });
  await sendChannelsState(ws);
  await sendDMState(ws);

  send(ws, { type: "joined", channel: ws.channel.name });
  send(ws, { type: "history", channel: ws.channel.name, messages: await loadHistory(ws.channel.id) });

  broadcastPresence(ws.channel.name);
  await broadcastSeen(ws.channel);

  ws.on("pong", () => (ws.isAlive = true));

  ws.on("message", async (buf) => {
    let msg;
    try { msg = JSON.parse(buf.toString("utf8")); } catch { return; }

    // set name
    if (msg.type === "hello" && typeof msg.name === "string") {
      ws.user.name = msg.name.trim().slice(0, 32) || "Гость";
      broadcastPresence(ws.channel.name);
      await broadcastSeen(ws.channel);

      await sendChannelsState(ws);
      await sendDMState(ws);
      return;
    }

    // create channel
    if (msg.type === "create_channel" && typeof msg.name === "string") {
      await getOrCreateChannel(msg.name);
      broadcastAll({ type: "channels", channels: (await listChannels()).map(c => c.name) });
      await sendChannelsStateToAll();
      return;
    }

    // join channel
    if (msg.type === "join" && typeof msg.channel === "string") {
      const prev = ws.channel;
      ws.channel = await getOrCreateChannel(msg.channel);
      ws.mode = "channel";
      ws.dm = null;

      send(ws, { type: "joined", channel: ws.channel.name });
      send(ws, { type: "history", channel: ws.channel.name, messages: await loadHistory(ws.channel.id) });

      if (prev?.name) broadcastPresence(prev.name);
      broadcastPresence(ws.channel.name);

      await broadcastSeen(ws.channel);
      await sendChannelsState(ws);
      return;
    }

    // channel seen
    if (msg.type === "seen" && typeof msg.seq === "number") {
      if (ws.mode !== "channel") return;
      const lastRead = Math.max(0, Math.floor(msg.seq));
      await setChannelRead(ws.channel.id, ws.user.name || "Гость", lastRead);

      await broadcastSeen(ws.channel);
      await sendChannelsState(ws);
      return;
    }

    // channel chat
    if (msg.type === "chat" && typeof msg.text === "string") {
      const text = msg.text.trim();
      if (!text) return;

      const saved = await saveMessage(ws.channel.id, ws.user.name || "Гость", text.slice(0, 2000));
      const message = { id: saved.id, at: saved.at, from: ws.user.name || "Гость", text: text.slice(0, 2000) };

      broadcastToChannel(ws.channel.name, { type: "chat", channel: ws.channel.name, message });

      await broadcastSeen(ws.channel);
      await sendChannelsStateToAll();
      return;
    }

    // open dm (create if needed)
    if (msg.type === "open_dm" && typeof msg.peer === "string") {
      const me = ws.user.name || "Гость";
      const peer = msg.peer.trim().slice(0, 32);
      if (!peer || peer === me) return;

      const chat = await getOrCreateDM(me, peer);
      const actualPeer = dmPeer(chat, me);

      ws.mode = "dm";
      ws.dm = { chatId: Number(chat.id), peer: actualPeer };

      send(ws, {
        type: "dm_joined",
        peer: actualPeer,
        chatId: Number(chat.id),
        messages: await loadDMHistory(chat.id),
      });

      await sendDMState(ws);
      return;
    }

    // dm seen
    if (msg.type === "dm_seen" && typeof msg.seq === "number" && typeof msg.chatId === "number") {
      const me = ws.user.name || "Гость";
      const chatId = Math.floor(msg.chatId);
      const lastRead = Math.max(0, Math.floor(msg.seq));
      await setDMRead(chatId, me, lastRead);
      await sendDMState(ws);
      return;
    }

    // dm send
    if (msg.type === "dm_send" && typeof msg.text === "string" && typeof msg.chatId === "number") {
      const me = ws.user.name || "Гость";
      const chatId = Math.floor(msg.chatId);
      const text = msg.text.trim();
      if (!text) return;

      // кто участники?
      const { rows } = await pool.query(
        `SELECT id, user_a, user_b FROM direct_chats WHERE id=$1 LIMIT 1`,
        [chatId]
      );
      if (!rows.length) return;
      const chat = rows[0];
      if (chat.user_a !== me && chat.user_b !== me) return;

      const peer = (chat.user_a === me) ? chat.user_b : chat.user_a;

      const saved = await saveDM(chatId, me, text.slice(0, 2000));
      const message = { id: saved.id, at: saved.at, from: me, text: text.slice(0, 2000) };

      // отправляем всем вкладкам обоих участников
      for (const c of wss.clients) {
        if (c.readyState !== 1) continue;
        const name = c.user?.name || "Гость";
        if (name === me || name === peer) {
          send(c, { type: "dm_message", chatId, peer: name === me ? peer : me, message });
        }
      }

      await sendDMStateToParticipants(me, peer);
      return;
    }
  });

  ws.on("close", async () => {
    if (ws.channel?.name) {
      broadcastPresence(ws.channel.name);
      await broadcastSeen(ws.channel);
    }
  });
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
