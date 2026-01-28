import express from "express";
import http from "http";
import { WebSocketServer } from "ws";
import pg from "pg";
import bcrypt from "bcryptjs";
import cookie from "cookie";
import crypto from "crypto";

const { Pool } = pg;

const app = express();
app.use(express.json());
app.use(express.static("public"));
app.get("/health", (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

const SUPERADMIN_EMAIL = (process.env.SUPERADMIN_EMAIL || "").trim().toLowerCase();

/* =========================
   Helpers
========================= */
function nowIso() {
  return new Date().toISOString();
}
function randToken() {
  return crypto.randomBytes(32).toString("hex");
}
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function normalizeName(name) {
  return String(name || "").trim().slice(0, 48) || "User";
}
function normalizeChannelName(name) {
  const safe = String(name || "").toLowerCase().trim().slice(0, 40);
  return safe.replace(/\s+/g, "-").replace(/[^a-z0-9\-_]/g, "") || "general";
}
function ok(res, data) {
  res.json({ ok: true, ...data });
}
function fail(res, status, code, message) {
  res.status(status).json({ ok: false, code, message });
}
async function queryOne(sql, params) {
  const { rows } = await pool.query(sql, params);
  return rows[0] || null;
}

/* =========================
   Online presence + sockets map
========================= */
const onlineCounts = new Map(); // userId -> count
const userSockets = new Map();  // userId -> Set<ws>

function setOnline(userId, delta) {
  const cur = onlineCounts.get(userId) || 0;
  const next = Math.max(0, cur + delta);
  if (next === 0) onlineCounts.delete(userId);
  else onlineCounts.set(userId, next);
  return { was: cur > 0, now: next > 0 };
}

function addSocket(userId, ws) {
  let set = userSockets.get(userId);
  if (!set) {
    set = new Set();
    userSockets.set(userId, set);
  }
  set.add(ws);
}
function removeSocket(userId, ws) {
  const set = userSockets.get(userId);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userSockets.delete(userId);
}

function sendToUser(userId, obj) {
  const set = userSockets.get(userId);
  if (!set) return;
  const payload = JSON.stringify(obj);
  for (const ws of set) {
    if (ws.readyState === 1) ws.send(payload);
  }
}
function broadcastAll(obj) {
  const payload = JSON.stringify(obj);
  for (const c of wss.clients) {
    if (c.readyState === 1) c.send(payload);
  }
}
function getOnlineUserIds() {
  return [...onlineCounts.keys()];
}

/* =========================
   Auth & Sessions
========================= */
async function getUserBySessionToken(sessionToken) {
  if (!sessionToken) return null;

  const row = await queryOne(
    `SELECT u.id, u.email, u.display_name, u.system_role, u.created_at
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > NOW()`,
    [sessionToken]
  );
  if (!row) return null;

  const email = String(row.email).toLowerCase();
  const isSuper = SUPERADMIN_EMAIL && email === SUPERADMIN_EMAIL;

  return {
    id: Number(row.id),
    email,
    displayName: row.display_name,
    systemRole: row.system_role, // MEMBER/ADMIN/OWNER
    isSuperadmin: Boolean(isSuper),
    createdAt: row.created_at,
  };
}

function getSessionTokenFromReq(req) {
  const raw = req.headers.cookie || "";
  const parsed = cookie.parse(raw || "");
  return parsed.session || "";
}

async function requireAuth(req, res, next) {
  const token = getSessionTokenFromReq(req);
  const user = await getUserBySessionToken(token);
  if (!user) return fail(res, 401, "UNAUTH", "Not authenticated");
  req.user = user;
  req.sessionToken = token;
  next();
}

function requireOwnerOrAdmin(req, res, next) {
  const u = req.user;
  if (u.isSuperadmin) return next();
  if (u.systemRole === "OWNER" || u.systemRole === "ADMIN") return next();
  return fail(res, 403, "FORBIDDEN", "Not enough permissions");
}
function requireOwner(req, res, next) {
  const u = req.user;
  if (u.isSuperadmin) return next();
  if (u.systemRole === "OWNER") return next();
  return fail(res, 403, "FORBIDDEN", "Owner only");
}

/* =========================
   Roles & Access (channels)
========================= */
async function getUserCustomRoleIds(userId) {
  const { rows } = await pool.query(
    `SELECT role_id FROM user_roles WHERE user_id = $1`,
    [userId]
  );
  return rows.map((r) => Number(r.role_id));
}

async function canAccessChannel(user, channelId) {
  if (user.isSuperadmin || user.systemRole === "OWNER") return true;

  const ch = await queryOne(`SELECT id, is_public FROM channels WHERE id=$1`, [channelId]);
  if (!ch) return false;
  if (ch.is_public) return true;

  const uacc = await queryOne(
    `SELECT 1 FROM channel_user_access WHERE channel_id=$1 AND user_id=$2`,
    [channelId, user.id]
  );
  if (uacc) return true;

  const roleIds = await getUserCustomRoleIds(user.id);
  if (!roleIds.length) return false;

  const racc = await queryOne(
    `SELECT 1 FROM channel_role_access WHERE channel_id=$1 AND role_id = ANY($2::int[])`,
    [channelId, roleIds]
  );
  return Boolean(racc);
}

/**
 * Каналы + unreadCount
 * ВАЖНО: unreadCount не считает сообщения, отправленные самим пользователем.
 */
async function listAccessibleChannelsWithUnread(user) {
  if (user.isSuperadmin || user.systemRole === "OWNER") {
    const { rows } = await pool.query(
      `
      SELECT
        c.id, c.name, c.is_public,
        COALESCE(lm.last_id, 0)::bigint AS last_message_id,
        COALESCE(cr.last_read_message_id, 0)::bigint AS last_read_message_id,
        COALESCE(uc.unread_count, 0)::int AS unread_count
      FROM channels c
      LEFT JOIN LATERAL (
        SELECT id AS last_id
        FROM channel_messages m
        WHERE m.channel_id = c.id
        ORDER BY id DESC
        LIMIT 1
      ) lm ON true
      LEFT JOIN channel_reads cr
        ON cr.channel_id = c.id AND cr.user_id = $1
      LEFT JOIN LATERAL (
        SELECT COUNT(*)::int AS unread_count
        FROM channel_messages m
        WHERE m.channel_id = c.id
          AND m.id > COALESCE(cr.last_read_message_id, 0)
          AND m.sender_user_id <> $1
      ) uc ON true
      ORDER BY c.name ASC
      LIMIT 200
      `,
      [user.id]
    );

    return rows.map((r) => ({
      id: Number(r.id),
      name: r.name,
      isPublic: r.is_public,
      lastMessageId: Number(r.last_message_id),
      unreadCount: Number(r.unread_count),
    }));
  }

  const roleIds = await getUserCustomRoleIds(user.id);

  const { rows } = await pool.query(
    `
    WITH accessible AS (
      SELECT DISTINCT c.id, c.name, c.is_public
      FROM channels c
      LEFT JOIN channel_user_access cua
        ON cua.channel_id = c.id AND cua.user_id = $1
      LEFT JOIN channel_role_access cra
        ON cra.channel_id = c.id AND (cra.role_id = ANY($2::int[]) OR $2::int[] IS NULL)
      WHERE c.is_public = true
         OR cua.user_id IS NOT NULL
         OR cra.role_id IS NOT NULL
    )
    SELECT
      a.id, a.name, a.is_public,
      COALESCE(lm.last_id, 0)::bigint AS last_message_id,
      COALESCE(cr.last_read_message_id, 0)::bigint AS last_read_message_id,
      COALESCE(uc.unread_count, 0)::int AS unread_count
    FROM accessible a
    LEFT JOIN LATERAL (
      SELECT id AS last_id
      FROM channel_messages m
      WHERE m.channel_id = a.id
      ORDER BY id DESC
      LIMIT 1
    ) lm ON true
    LEFT JOIN channel_reads cr
      ON cr.channel_id = a.id AND cr.user_id = $1
    LEFT JOIN LATERAL (
      SELECT COUNT(*)::int AS unread_count
      FROM channel_messages m
      WHERE m.channel_id = a.id
        AND m.id > COALESCE(cr.last_read_message_id, 0)
        AND m.sender_user_id <> $1
    ) uc ON true
    ORDER BY a.name ASC
    LIMIT 200
    `,
    [user.id, roleIds.length ? roleIds : null]
  );

  return rows.map((r) => ({
    id: Number(r.id),
    name: r.name,
    isPublic: r.is_public,
    lastMessageId: Number(r.last_message_id),
    unreadCount: Number(r.unread_count),
  }));
}

async function auditLog(actorUserId, action, metaObj) {
  await pool.query(
    `INSERT INTO audit_logs (actor_user_id, action, meta)
     VALUES ($1, $2, $3::jsonb)`,
    [actorUserId, action, JSON.stringify(metaObj || {})]
  );
}

/* =========================
   Read receipts (channels, вариант B)
   - total = все пользователи, у кого есть доступ (плюс OWNER + SUPERADMIN)
   - readCount = сколько из них last_read >= messageId
========================= */
async function getSuperadminUserIdOrNull() {
  if (!SUPERADMIN_EMAIL) return null;
  const row = await queryOne(`SELECT id FROM users WHERE lower(email)=$1`, [SUPERADMIN_EMAIL]);
  return row ? Number(row.id) : null;
}

async function getEligibleUserIdsForChannel(channelId) {
  const ch = await queryOne(`SELECT id, is_public FROM channels WHERE id=$1`, [channelId]);
  if (!ch) return [];

  const superId = await getSuperadminUserIdOrNull();

  if (ch.is_public) {
    const { rows } = await pool.query(`SELECT id FROM users ORDER BY id ASC`);
    const ids = new Set(rows.map(r => Number(r.id)));
    const ownerRows = await pool.query(`SELECT id FROM users WHERE system_role='OWNER'`);
    for (const r of ownerRows.rows) ids.add(Number(r.id));
    if (superId) ids.add(superId);
    return [...ids];
  }

  const { rows } = await pool.query(
    `
    WITH role_users AS (
      SELECT DISTINCT ur.user_id AS id
      FROM channel_role_access cra
      JOIN user_roles ur ON ur.role_id = cra.role_id
      WHERE cra.channel_id = $1
    ),
    direct_users AS (
      SELECT DISTINCT user_id AS id
      FROM channel_user_access
      WHERE channel_id = $1
    ),
    owners AS (
      SELECT id FROM users WHERE system_role='OWNER'
    ),
    super AS (
      SELECT id FROM users WHERE $2::int IS NOT NULL AND id = $2::int
    )
    SELECT DISTINCT id FROM (
      SELECT id FROM role_users
      UNION ALL SELECT id FROM direct_users
      UNION ALL SELECT id FROM owners
      UNION ALL SELECT id FROM super
    ) t
    `,
    [channelId, superId]
  );

  return rows.map(r => Number(r.id));
}

async function upsertChannelRead(channelId, userId, lastReadMessageId) {
  await pool.query(
    `
    INSERT INTO channel_reads (channel_id, user_id, last_read_message_id, updated_at)
    VALUES ($1,$2,$3,NOW())
    ON CONFLICT (channel_id, user_id)
    DO UPDATE SET last_read_message_id = GREATEST(channel_reads.last_read_message_id, EXCLUDED.last_read_message_id),
                  updated_at = NOW()
    `,
    [channelId, userId, lastReadMessageId]
  );
}

async function getReadProgressForMessage(channelId, messageId) {
  const eligibleIds = await getEligibleUserIdsForChannel(channelId);
  if (!eligibleIds.length) return { readCount: 0, total: 0 };

  const { rows } = await pool.query(
    `
    WITH eligible AS (SELECT unnest($2::int[]) AS user_id)
    SELECT
      COUNT(*) FILTER (WHERE cr.last_read_message_id >= $3)::int AS read_count,
      COUNT(*)::int AS total
    FROM eligible e
    LEFT JOIN channel_reads cr
      ON cr.channel_id = $1 AND cr.user_id = e.user_id
    `,
    [channelId, eligibleIds, messageId]
  );

  return { readCount: Number(rows[0]?.read_count || 0), total: Number(rows[0]?.total || 0) };
}

/**
 * Батч: берём last_read по eligible и считаем readCount для набора messageIds.
 * Это нужно, чтобы при одном "read" корректно обновлялись счётчики не только у последнего сообщения.
 */
async function getReadProgressBatch(channelId, messageIds) {
  const eligibleIds = await getEligibleUserIdsForChannel(channelId);
  const total = eligibleIds.length;
  if (!total || !messageIds.length) return { total, items: [] };

  const { rows } = await pool.query(
    `SELECT user_id, last_read_message_id
     FROM channel_reads
     WHERE channel_id=$1 AND user_id = ANY($2::int[])`,
    [channelId, eligibleIds]
  );

  const lastReadByUser = new Map();
  for (const rr of rows) lastReadByUser.set(Number(rr.user_id), Number(rr.last_read_message_id));

  const items = messageIds.map((mid) => {
    let readCount = 0;
    for (const uid of eligibleIds) {
      const last = lastReadByUser.get(uid) || 0;
      if (last >= mid) readCount += 1;
    }
    return { messageId: mid, readCount, total };
  });

  return { total, items };
}

async function getLastChannelMessageIds(channelId, limit = 30) {
  const { rows } = await pool.query(
    `SELECT id FROM channel_messages WHERE channel_id=$1 ORDER BY id DESC LIMIT $2`,
    [channelId, limit]
  );
  return rows.map(r => Number(r.id)).reverse();
}

/* =========================
   DM + unread
========================= */
async function ensureDmChat(userAId, userBId) {
  const a = Math.min(userAId, userBId);
  const b = Math.max(userAId, userBId);

  const existing = await queryOne(
    `SELECT id FROM dm_chats WHERE user_a_id=$1 AND user_b_id=$2`,
    [a, b]
  );
  if (existing) return Number(existing.id);

  const row = await queryOne(
    `INSERT INTO dm_chats (user_a_id, user_b_id, created_at)
     VALUES ($1,$2,NOW())
     RETURNING id`,
    [a, b]
  );
  return Number(row.id);
}

async function canAccessDmChat(userId, chatId) {
  const row = await queryOne(
    `SELECT 1 FROM dm_chats WHERE id=$1 AND (user_a_id=$2 OR user_b_id=$2)`,
    [chatId, userId]
  );
  return Boolean(row);
}

async function getDmOtherUserId(chatId, meId) {
  const row = await queryOne(
    `SELECT user_a_id, user_b_id FROM dm_chats WHERE id=$1`,
    [chatId]
  );
  if (!row) return null;
  const a = Number(row.user_a_id);
  const b = Number(row.user_b_id);
  return a === meId ? b : a;
}

async function upsertDmRead(chatId, userId, lastReadMessageId) {
  await pool.query(
    `
    INSERT INTO dm_reads (chat_id, user_id, last_read_message_id, updated_at)
    VALUES ($1,$2,$3,NOW())
    ON CONFLICT (chat_id, user_id)
    DO UPDATE SET last_read_message_id = GREATEST(dm_reads.last_read_message_id, EXCLUDED.last_read_message_id),
                  updated_at = NOW()
    `,
    [chatId, userId, lastReadMessageId]
  );
}

async function getDmReadProgress(chatId, messageId) {
  const { rows } = await pool.query(
    `
    WITH participants AS (
      SELECT user_a_id AS user_id FROM dm_chats WHERE id=$1
      UNION ALL
      SELECT user_b_id AS user_id FROM dm_chats WHERE id=$1
    )
    SELECT
      COUNT(*) FILTER (WHERE dr.last_read_message_id >= $2)::int AS read_count,
      COUNT(*)::int AS total
    FROM participants p
    LEFT JOIN dm_reads dr
      ON dr.chat_id=$1 AND dr.user_id=p.user_id
    `,
    [chatId, messageId]
  );
  return { readCount: Number(rows[0]?.read_count || 0), total: Number(rows[0]?.total || 0) };
}

async function loadDmHistory(chatId, limit = 200) {
  const { rows } = await pool.query(
    `SELECT m.id,
            m.text,
            EXTRACT(EPOCH FROM m.created_at)*1000 AS at,
            u.display_name,
            u.id AS sender_id
     FROM dm_messages m
     JOIN users u ON u.id = m.sender_user_id
     WHERE m.chat_id=$1
     ORDER BY m.id DESC
     LIMIT $2`,
    [chatId, limit]
  );

  const messages = rows.reverse().map(r => ({
    id: Number(r.id),
    text: r.text,
    at: Number(r.at),
    from: r.display_name,
    fromId: Number(r.sender_id),
    read: { readCount: 0, total: 0 },
  }));

  const tail = messages.slice(Math.max(0, messages.length - 50));
  for (const m of tail) {
    m.read = await getDmReadProgress(chatId, m.id);
  }

  return messages;
}

async function saveDmMessage(chatId, senderUserId, text) {
  const row = await queryOne(
    `INSERT INTO dm_messages (chat_id, sender_user_id, text, created_at)
     VALUES ($1,$2,$3,NOW())
     RETURNING id, EXTRACT(EPOCH FROM created_at)*1000 AS at`,
    [chatId, senderUserId, text]
  );
  return { id: Number(row.id), at: Number(row.at) };
}

async function getDmParticipants(chatId) {
  const row = await queryOne(`SELECT user_a_id, user_b_id FROM dm_chats WHERE id=$1`, [chatId]);
  if (!row) return [];
  return [Number(row.user_a_id), Number(row.user_b_id)];
}

/* =========================
   DB migrate + seed
========================= */
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      system_role TEXT NOT NULL DEFAULT 'MEMBER',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS roles (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_roles (
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, role_id)
    );

    CREATE TABLE IF NOT EXISTS channels (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      is_public BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS channel_role_access (
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      PRIMARY KEY (channel_id, role_id)
    );

    CREATE TABLE IF NOT EXISTS channel_user_access (
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (channel_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS channel_messages (
      id BIGSERIAL PRIMARY KEY,
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      sender_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS channel_reads (
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      last_read_message_id BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (channel_id, user_id)
    );

    -- DM
    CREATE TABLE IF NOT EXISTS dm_chats (
      id BIGSERIAL PRIMARY KEY,
      user_a_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      user_b_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_a_id, user_b_id)
    );

    CREATE TABLE IF NOT EXISTS dm_messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id BIGINT NOT NULL REFERENCES dm_chats(id) ON DELETE CASCADE,
      sender_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dm_reads (
      chat_id BIGINT NOT NULL REFERENCES dm_chats(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      last_read_message_id BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (chat_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      meta JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE channels ADD COLUMN IF NOT EXISTS is_public BOOLEAN NOT NULL DEFAULT true;`);
  await pool.query(`ALTER TABLE channels ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();`);

  await pool.query(
    `INSERT INTO channels (name, is_public)
     VALUES ($1, $2)
     ON CONFLICT (name) DO NOTHING`,
    ["general", true]
  );

  const seeds = [
    { name: "worker", display: "Рабочий" },
    { name: "manager", display: "Менеджер" },
    { name: "director", display: "Директор" },
  ];
  for (const r of seeds) {
    await pool.query(
      `INSERT INTO roles (name, display_name)
       VALUES ($1, $2)
       ON CONFLICT (name) DO NOTHING`,
      [r.name, r.display]
    );
  }

  // индексы (ускоряют unread/last)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_channel_messages_channel_id_id ON channel_messages(channel_id, id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_channel_messages_channel_sender_id_id ON channel_messages(channel_id, sender_user_id, id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_dm_messages_chat_id_id ON dm_messages(chat_id, id);`);
}

/* =========================
   REST API
========================= */
app.get("/api/positions", async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, display_name FROM roles ORDER BY id ASC LIMIT 200`
  );
  ok(res, {
    positions: rows.map((r) => ({
      id: Number(r.id),
      name: r.name,
      displayName: r.display_name,
    })),
  });
});

app.post("/api/register", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const displayName = normalizeName(req.body.displayName);
  const positionRoleId = Number(req.body.positionRoleId || 0);

  if (!isValidEmail(email)) return fail(res, 400, "BAD_EMAIL", "Invalid email");
  if (password.length < 6) return fail(res, 400, "BAD_PASSWORD", "Password must be at least 6 chars");
  if (!positionRoleId) return fail(res, 400, "BAD_POSITION", "Choose a position");

  const existing = await queryOne(`SELECT 1 FROM users WHERE email=$1`, [email]);
  if (existing) return fail(res, 409, "EMAIL_TAKEN", "Email already registered");

  const hash = await bcrypt.hash(password, 10);

  const countRow = await queryOne(`SELECT COUNT(*)::int AS c FROM users`, []);
  const isFirst = Number(countRow?.c || 0) === 0;
  const systemRole = isFirst ? "OWNER" : "MEMBER";

  const user = await queryOne(
    `INSERT INTO users (email, password_hash, display_name, system_role)
     VALUES ($1,$2,$3,$4)
     RETURNING id, email, display_name, system_role`,
    [email, hash, displayName, systemRole]
  );

  await pool.query(
    `INSERT INTO user_roles (user_id, role_id)
     VALUES ($1,$2)
     ON CONFLICT DO NOTHING`,
    [user.id, positionRoleId]
  );

  const token = randToken();
  await pool.query(
    `INSERT INTO sessions (token, user_id, expires_at)
     VALUES ($1,$2, NOW() + INTERVAL '30 days')`,
    [token, user.id]
  );

  res.setHeader(
    "Set-Cookie",
    cookie.serialize("session", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 60 * 60 * 24 * 30,
    })
  );

  await auditLog(user.id, "REGISTER", { email, systemRole, at: nowIso() });

  ok(res, {
    me: {
      id: Number(user.id),
      email: user.email,
      displayName: user.display_name,
      systemRole: user.system_role,
    },
  });
});

app.post("/api/login", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!isValidEmail(email)) return fail(res, 400, "BAD_EMAIL", "Invalid email");
  if (!password) return fail(res, 400, "BAD_PASSWORD", "Password required");

  const row = await queryOne(
    `SELECT id, email, password_hash, display_name, system_role
     FROM users WHERE email=$1`,
    [email]
  );
  if (!row) return fail(res, 401, "INVALID_LOGIN", "Wrong email or password");

  const okPass = await bcrypt.compare(password, row.password_hash);
  if (!okPass) return fail(res, 401, "INVALID_LOGIN", "Wrong email or password");

  const token = randToken();
  await pool.query(
    `INSERT INTO sessions (token, user_id, expires_at)
     VALUES ($1,$2, NOW() + INTERVAL '30 days')`,
    [token, row.id]
  );

  res.setHeader(
    "Set-Cookie",
    cookie.serialize("session", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 60 * 60 * 24 * 30,
    })
  );

  await auditLog(Number(row.id), "LOGIN", { at: nowIso() });

  ok(res, {
    me: {
      id: Number(row.id),
      email: row.email,
      displayName: row.display_name,
      systemRole: row.system_role,
    },
  });
});

app.post("/api/logout", requireAuth, async (req, res) => {
  await pool.query(`DELETE FROM sessions WHERE token=$1`, [req.sessionToken]);
  res.setHeader(
    "Set-Cookie",
    cookie.serialize("session", "", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 0,
    })
  );
  await auditLog(req.user.id, "LOGOUT", { at: nowIso() });
  ok(res, {});
});

app.get("/api/me", requireAuth, async (req, res) => {
  const roleIds = await getUserCustomRoleIds(req.user.id);
  const { rows } = await pool.query(
    `SELECT id, name, display_name FROM roles WHERE id = ANY($1::int[])`,
    [roleIds.length ? roleIds : [0]]
  );
  ok(res, {
    me: req.user,
    customRoles: rows.map((r) => ({
      id: Number(r.id),
      name: r.name,
      displayName: r.display_name,
    })),
  });
});

app.get("/api/channels", requireAuth, async (req, res) => {
  const channels = await listAccessibleChannelsWithUnread(req.user);
  ok(res, { channels });
});

app.get("/api/users", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, display_name, email, system_role
     FROM users
     WHERE id <> $1
     ORDER BY display_name ASC
     LIMIT 500`,
    [req.user.id]
  );
  ok(res, {
    users: rows.map(u => ({
      id: Number(u.id),
      displayName: u.display_name,
      email: u.email,
      systemRole: u.system_role,
    }))
  });
});

app.get("/api/dm", requireAuth, async (req, res) => {
  const meId = req.user.id;
  const { rows } = await pool.query(
    `
    SELECT
      c.id,
      c.user_a_id,
      c.user_b_id,
      u1.display_name AS a_name,
      u2.display_name AS b_name,
      u1.email AS a_email,
      u2.email AS b_email,
      COALESCE(dr.last_read_message_id, 0)::bigint AS last_read_message_id,
      COALESCE(lm.id, 0)::bigint AS last_message_id,
      lm.text AS last_text,
      EXTRACT(EPOCH FROM lm.created_at)*1000 AS last_at,
      COALESCE(uc.unread_count, 0)::int AS unread_count
    FROM dm_chats c
    JOIN users u1 ON u1.id = c.user_a_id
    JOIN users u2 ON u2.id = c.user_b_id
    LEFT JOIN dm_reads dr
      ON dr.chat_id = c.id AND dr.user_id = $1
    LEFT JOIN LATERAL (
      SELECT id, text, created_at
      FROM dm_messages m
      WHERE m.chat_id = c.id
      ORDER BY m.id DESC
      LIMIT 1
    ) lm ON true
    LEFT JOIN LATERAL (
      SELECT COUNT(*)::int AS unread_count
      FROM dm_messages m
      WHERE m.chat_id = c.id
        AND m.id > COALESCE(dr.last_read_message_id, 0)
        AND m.sender_user_id <> $1
    ) uc ON true
    WHERE c.user_a_id = $1 OR c.user_b_id = $1
    ORDER BY COALESCE(lm.id, 0) DESC, c.id DESC
    LIMIT 200
    `,
    [meId]
  );

  const chats = rows.map(r => {
    const a = Number(r.user_a_id);
    const b = Number(r.user_b_id);
    const otherId = a === meId ? b : a;
    const otherName = a === meId ? r.b_name : r.a_name;
    const otherEmail = a === meId ? r.b_email : r.a_email;

    return {
      id: Number(r.id),
      otherUser: { id: otherId, displayName: otherName, email: otherEmail },
      lastMessageId: Number(r.last_message_id || 0),
      unreadCount: Number(r.unread_count || 0),
      last: Number(r.last_message_id || 0) ? {
        id: Number(r.last_message_id),
        text: r.last_text,
        at: Number(r.last_at),
      } : null
    };
  });

  ok(res, { chats });
});

app.post("/api/dm/open", requireAuth, async (req, res) => {
  const otherUserId = Number(req.body.userId || 0);
  if (!otherUserId) return fail(res, 400, "BAD_INPUT", "userId required");
  if (otherUserId === req.user.id) return fail(res, 400, "BAD_INPUT", "cannot dm yourself");

  const other = await queryOne(`SELECT id FROM users WHERE id=$1`, [otherUserId]);
  if (!other) return fail(res, 404, "NOT_FOUND", "User not found");

  const chatId = await ensureDmChat(req.user.id, otherUserId);
  await auditLog(req.user.id, "DM_OPEN", { chatId, withUserId: otherUserId, at: nowIso() });
  ok(res, { chatId });
});

/* ===== Admin endpoints (как было) ===== */
app.get("/api/admin/users", requireAuth, requireOwnerOrAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, display_name, system_role, created_at
     FROM users
     ORDER BY id ASC
     LIMIT 500`
  );
  ok(res, {
    users: rows.map((u) => ({
      id: Number(u.id),
      email: u.email,
      displayName: u.display_name,
      systemRole: u.system_role,
      createdAt: u.created_at,
    })),
  });
});

app.get("/api/admin/roles", requireAuth, requireOwnerOrAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, display_name FROM roles ORDER BY id ASC LIMIT 200`
  );
  ok(res, {
    roles: rows.map((r) => ({ id: Number(r.id), name: r.name, displayName: r.display_name })),
  });
});

app.get("/api/admin/users/:id/roles", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  if (!userId) return fail(res, 400, "BAD_INPUT", "bad user id");

  const { rows } = await pool.query(
    `SELECT r.id, r.name, r.display_name
     FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     WHERE ur.user_id = $1
     ORDER BY r.id ASC`,
    [userId]
  );

  ok(res, {
    roles: rows.map((r) => ({ id: Number(r.id), name: r.name, displayName: r.display_name })),
  });
});

app.post("/api/admin/roles", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const name = String(req.body.name || "").trim().toLowerCase().slice(0, 32).replace(/\s+/g, "-");
  const displayName = String(req.body.displayName || "").trim().slice(0, 48);
  if (!name || !displayName) return fail(res, 400, "BAD_ROLE", "Role name/displayName required");

  const row = await queryOne(
    `INSERT INTO roles (name, display_name)
     VALUES ($1,$2)
     ON CONFLICT (name) DO NOTHING
     RETURNING id, name, display_name`,
    [name, displayName]
  );
  if (!row) return fail(res, 409, "ROLE_EXISTS", "Role already exists");

  await auditLog(req.user.id, "ROLE_CREATE", { name, displayName, at: nowIso() });
  ok(res, { role: { id: Number(row.id), name: row.name, displayName: row.display_name } });
});

app.post("/api/admin/users/:id/roles", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  const roleId = Number(req.body.roleId || 0);
  if (!userId || !roleId) return fail(res, 400, "BAD_INPUT", "userId/roleId required");

  const target = await queryOne(`SELECT id FROM users WHERE id=$1`, [userId]);
  if (!target) return fail(res, 404, "NOT_FOUND", "User not found");

  await pool.query(
    `INSERT INTO user_roles (user_id, role_id)
     VALUES ($1,$2)
     ON CONFLICT DO NOTHING`,
    [userId, roleId]
  );

  await auditLog(req.user.id, "USER_ROLE_ADD", { userId, roleId, at: nowIso() });
  ok(res, {});
});

app.delete("/api/admin/users/:id/roles/:roleId", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  const roleId = Number(req.params.roleId);
  if (!userId || !roleId) return fail(res, 400, "BAD_INPUT", "bad ids");

  await pool.query(`DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, [userId, roleId]);
  await auditLog(req.user.id, "USER_ROLE_REMOVE", { userId, roleId, at: nowIso() });
  ok(res, {});
});

app.get("/api/admin/channels", requireAuth, requireOwnerOrAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, is_public FROM channels ORDER BY name ASC LIMIT 200`
  );
  ok(res, { channels: rows.map(c => ({ id: Number(c.id), name: c.name, isPublic: c.is_public })) });
});

app.post("/api/admin/channels", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const name = normalizeChannelName(req.body.name);
  const isPublic = Boolean(req.body.isPublic);

  const ch = await queryOne(
    `INSERT INTO channels (name, is_public)
     VALUES ($1,$2)
     ON CONFLICT (name) DO NOTHING
     RETURNING id, name, is_public`,
    [name, isPublic]
  );
  if (!ch) return fail(res, 409, "CHANNEL_EXISTS", "Channel already exists");

  await auditLog(req.user.id, "CHANNEL_CREATE", { name, isPublic, at: nowIso() });
  ok(res, { channel: { id: Number(ch.id), name: ch.name, isPublic: ch.is_public } });
});

app.get("/api/admin/channels/:id/access", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const channelId = Number(req.params.id);
  const ch = await queryOne(`SELECT id FROM channels WHERE id=$1`, [channelId]);
  if (!ch) return fail(res, 404, "NOT_FOUND", "Channel not found");

  const r = await pool.query(`SELECT role_id FROM channel_role_access WHERE channel_id=$1`, [channelId]);
  const u = await pool.query(`SELECT user_id FROM channel_user_access WHERE channel_id=$1`, [channelId]);

  ok(res, {
    roleIds: r.rows.map(x => Number(x.role_id)),
    userIds: u.rows.map(x => Number(x.user_id)),
  });
});

app.post("/api/admin/channels/:id/access", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const channelId = Number(req.params.id);
  const roleIds = Array.isArray(req.body.roleIds) ? req.body.roleIds.map(Number).filter(Boolean) : [];
  const userIds = Array.isArray(req.body.userIds) ? req.body.userIds.map(Number).filter(Boolean) : [];

  const ch = await queryOne(`SELECT id FROM channels WHERE id=$1`, [channelId]);
  if (!ch) return fail(res, 404, "NOT_FOUND", "Channel not found");

  await pool.query(`DELETE FROM channel_role_access WHERE channel_id=$1`, [channelId]);
  await pool.query(`DELETE FROM channel_user_access WHERE channel_id=$1`, [channelId]);

  for (const rid of roleIds) {
    await pool.query(
      `INSERT INTO channel_role_access (channel_id, role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [channelId, rid]
    );
  }
  for (const uid of userIds) {
    await pool.query(
      `INSERT INTO channel_user_access (channel_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [channelId, uid]
    );
  }

  await auditLog(req.user.id, "CHANNEL_ACCESS_SET", { channelId, roleIds, userIds, at: nowIso() });
  ok(res, {});
});

app.get("/api/audit", requireAuth, requireOwner, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT a.id, a.action, a.meta, a.created_at, u.email, u.display_name
     FROM audit_logs a
     JOIN users u ON u.id = a.actor_user_id
     ORDER BY a.id DESC
     LIMIT 200`
  );

  ok(res, {
    logs: rows.map((r) => ({
      id: Number(r.id),
      action: r.action,
      meta: r.meta,
      at: r.created_at,
      actor: { email: r.email, displayName: r.display_name },
    })),
  });
});

app.get("/api/admin/dm/chats", requireAuth, requireOwner, async (_req, res) => {
  const { rows } = await pool.query(
    `
    SELECT c.id,
           c.user_a_id,
           c.user_b_id,
           u1.display_name AS a_name,
           u2.display_name AS b_name,
           u1.email AS a_email,
           u2.email AS b_email,
           lm.id AS last_message_id,
           lm.text AS last_text,
           EXTRACT(EPOCH FROM lm.created_at)*1000 AS last_at
    FROM dm_chats c
    JOIN users u1 ON u1.id = c.user_a_id
    JOIN users u2 ON u2.id = c.user_b_id
    LEFT JOIN LATERAL (
      SELECT id, text, created_at
      FROM dm_messages m
      WHERE m.chat_id = c.id
      ORDER BY m.id DESC
      LIMIT 1
    ) lm ON true
    ORDER BY COALESCE(lm.id, 0) DESC, c.id DESC
    LIMIT 300
    `
  );

  ok(res, {
    chats: rows.map(r => ({
      id: Number(r.id),
      a: { id: Number(r.user_a_id), displayName: r.a_name, email: r.a_email },
      b: { id: Number(r.user_b_id), displayName: r.b_name, email: r.b_email },
      last: r.last_message_id ? { id: Number(r.last_message_id), text: r.last_text, at: Number(r.last_at) } : null
    }))
  });
});

app.get("/api/admin/dm/chats/:id/messages", requireAuth, requireOwner, async (req, res) => {
  const chatId = Number(req.params.id);
  if (!chatId) return fail(res, 400, "BAD_INPUT", "bad chat id");

  const chat = await queryOne(`SELECT user_a_id, user_b_id FROM dm_chats WHERE id=$1`, [chatId]);
  if (!chat) return fail(res, 404, "NOT_FOUND", "Chat not found");

  const { rows } = await pool.query(
    `SELECT m.id, m.text, EXTRACT(EPOCH FROM m.created_at)*1000 AS at,
            u.id AS sender_id, u.display_name AS sender_name, u.email AS sender_email
     FROM dm_messages m
     JOIN users u ON u.id = m.sender_user_id
     WHERE m.chat_id=$1
     ORDER BY m.id ASC
     LIMIT 500`,
    [chatId]
  );

  await auditLog(req.user.id, "DM_AUDIT_VIEW", {
    chatId,
    userAId: Number(chat.user_a_id),
    userBId: Number(chat.user_b_id),
    at: nowIso(),
  });

  ok(res, {
    messages: rows.map(r => ({
      id: Number(r.id),
      at: Number(r.at),
      text: r.text,
      fromId: Number(r.sender_id),
      from: r.sender_name,
      fromEmail: r.sender_email,
    }))
  });
});

/* =========================
   WebSocket (channels + DM + receipts + presence + unread notices)
========================= */
async function wsGetUserFromReq(req) {
  const raw = req.headers.cookie || "";
  const parsed = cookie.parse(raw || "");
  const token = parsed.session || "";
  return await getUserBySessionToken(token);
}
function wsSend(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}
async function wsSendInit(ws) {
  const channels = await listAccessibleChannelsWithUnread(ws.user);
  wsSend(ws, {
    type: "init",
    me: ws.user,
    channels,
    onlineUserIds: getOnlineUserIds(),
  });
}

async function loadChannelHistoryWithReads(channelId, limit = 200) {
  const { rows } = await pool.query(
    `SELECT m.id, m.text, EXTRACT(EPOCH FROM m.created_at)*1000 AS at,
            u.display_name, u.id AS sender_id
     FROM channel_messages m
     JOIN users u ON u.id = m.sender_user_id
     WHERE m.channel_id=$1
     ORDER BY m.id DESC
     LIMIT $2`,
    [channelId, limit]
  );

  const messages = rows.reverse().map(r => ({
    id: Number(r.id),
    text: r.text,
    at: Number(r.at),
    from: r.display_name,
    fromId: Number(r.sender_id),
    read: { readCount: 0, total: 0 },
  }));

  if (!messages.length) return { messages, totalEligible: 0, lastMessageId: 0 };

  const tailIds = messages.slice(Math.max(0, messages.length - 30)).map(m => m.id);
  const batch = await getReadProgressBatch(channelId, tailIds);
  const map = new Map(batch.items.map(x => [x.messageId, { readCount: x.readCount, total: x.total }]));
  for (const m of messages) {
    const rr = map.get(m.id);
    if (rr) m.read = rr;
  }

  const lastMessageId = messages[messages.length - 1].id;
  return { messages, totalEligible: batch.total || 0, lastMessageId };
}

async function saveChannelMessage(channelId, senderUserId, text) {
  const row = await queryOne(
    `INSERT INTO channel_messages (channel_id, sender_user_id, text)
     VALUES ($1,$2,$3)
     RETURNING id, EXTRACT(EPOCH FROM created_at)*1000 AS at`,
    [channelId, senderUserId, text]
  );
  return { id: Number(row.id), at: Number(row.at) };
}

function broadcastToChannelId(channelId, obj) {
  const payload = JSON.stringify(obj);
  for (const c of wss.clients) {
    if (c.readyState === 1 && c.channelId === channelId) c.send(payload);
  }
}
function broadcastToDmChatId(chatId, obj) {
  const payload = JSON.stringify(obj);
  for (const c of wss.clients) {
    if (c.readyState === 1 && c.dmChatId === chatId) c.send(payload);
  }
}

async function broadcastChannelReadBatch(channelId) {
  const ids = await getLastChannelMessageIds(channelId, 30);
  const batch = await getReadProgressBatch(channelId, ids);
  broadcastToChannelId(channelId, { type: "read_progress_batch", channelId, items: batch.items });
}

wss.on("connection", async (ws, req) => {
  const user = await wsGetUserFromReq(req);
  if (!user) {
    ws.close(4401, "unauthorized");
    return;
  }

  ws.user = user;
  ws.channelId = null;
  ws.dmChatId = null;
  ws.isAlive = true;

  addSocket(user.id, ws);

  const { was, now } = setOnline(user.id, +1);
  if (!was && now) broadcastAll({ type: "presence_update", userId: user.id, online: true });

  ws.on("close", () => {
    removeSocket(user.id, ws);
    const { was: w, now: n } = setOnline(user.id, -1);
    if (w && !n) broadcastAll({ type: "presence_update", userId: user.id, online: false });
  });

  ws.on("pong", () => (ws.isAlive = true));

  await wsSendInit(ws);

  ws.on("message", async (buf) => {
    let msg;
    try { msg = JSON.parse(buf.toString("utf8")); } catch { return; }

    /* ===== Channels ===== */
    if (msg.type === "join" && typeof msg.channelId === "number") {
      const channelId = Math.floor(msg.channelId);
      const allowed = await canAccessChannel(ws.user, channelId);
      if (!allowed) {
        wsSend(ws, { type: "error", code: "NO_ACCESS", message: "No access to channel" });
        return;
      }
      ws.channelId = channelId;
      ws.dmChatId = null;

      const history = await loadChannelHistoryWithReads(channelId, 200);
      wsSend(ws, { type: "joined", channelId, totalEligible: history.totalEligible });
      wsSend(ws, { type: "history", channelId, messages: history.messages, totalEligible: history.totalEligible });

      if (history.lastMessageId) {
        await upsertChannelRead(channelId, ws.user.id, history.lastMessageId);

        // батч прогресса, чтобы всем обновились "прочитано X/Y"
        await broadcastChannelReadBatch(channelId);

        // обновим unread у этого пользователя (в списке слева)
        sendToUser(ws.user.id, { type: "refresh_lists" });
      }
      return;
    }

    if (msg.type === "chat" && typeof msg.text === "string") {
      const text = msg.text.trim();
      if (!text) return;
      if (!ws.channelId) return;

      const allowed = await canAccessChannel(ws.user, ws.channelId);
      if (!allowed) return;

      const saved = await saveChannelMessage(ws.channelId, ws.user.id, text.slice(0, 2000));

      // sender read
      await upsertChannelRead(ws.channelId, ws.user.id, saved.id);
      const prog = await getReadProgressForMessage(ws.channelId, saved.id);

      broadcastToChannelId(ws.channelId, {
        type: "chat",
        channelId: ws.channelId,
        message: {
          id: saved.id,
          at: saved.at,
          from: ws.user.displayName,
          fromId: ws.user.id,
          text: text.slice(0, 2000),
          read: { readCount: prog.readCount, total: prog.total },
        }
      });

      // обновим батч (вдруг sender = первый читатель и т.п.)
      await broadcastChannelReadBatch(ws.channelId);

      // уведомление всем: чтобы обновили unread бейджи
      broadcastAll({ type: "channel_notice", channelId: ws.channelId });

      return;
    }

    if (msg.type === "read" && typeof msg.channelId === "number" && typeof msg.lastReadMessageId === "number") {
      const channelId = Math.floor(msg.channelId);
      const lastReadMessageId = Math.floor(msg.lastReadMessageId);
      const allowed = await canAccessChannel(ws.user, channelId);
      if (!allowed) return;

      await upsertChannelRead(channelId, ws.user.id, lastReadMessageId);

      // батч обновление прогресса для последних сообщений
      await broadcastChannelReadBatch(channelId);

      // обновим unread у текущего пользователя
      sendToUser(ws.user.id, { type: "refresh_lists" });
      return;
    }

    /* ===== DM ===== */
    if (msg.type === "dm_join" && typeof msg.chatId === "number") {
      const chatId = Math.floor(msg.chatId);
      const allowed = await canAccessDmChat(ws.user.id, chatId);
      if (!allowed) {
        wsSend(ws, { type: "error", code: "NO_ACCESS", message: "No access to DM" });
        return;
      }

      ws.dmChatId = chatId;
      ws.channelId = null;

      const otherId = await getDmOtherUserId(chatId, ws.user.id);
      const other = otherId ? await queryOne(`SELECT id, display_name, email FROM users WHERE id=$1`, [otherId]) : null;

      const messages = await loadDmHistory(chatId, 200);
      wsSend(ws, {
        type: "dm_history",
        chatId,
        otherUser: other ? { id: Number(other.id), displayName: other.display_name, email: other.email } : null,
        messages
      });

      if (messages.length) {
        const lastId = messages[messages.length - 1].id;
        await upsertDmRead(chatId, ws.user.id, lastId);
        const prog = await getDmReadProgress(chatId, lastId);
        broadcastToDmChatId(chatId, { type: "dm_read_progress", chatId, messageId: lastId, read: prog });

        // refresh list for unread
        sendToUser(ws.user.id, { type: "refresh_lists" });
      }
      return;
    }

    if (msg.type === "dm_chat" && typeof msg.text === "string") {
      const text = msg.text.trim();
      if (!text) return;
      if (!ws.dmChatId) return;

      const chatId = ws.dmChatId;
      const allowed = await canAccessDmChat(ws.user.id, chatId);
      if (!allowed) return;

      const saved = await saveDmMessage(chatId, ws.user.id, text.slice(0, 2000));
      await upsertDmRead(chatId, ws.user.id, saved.id);
      const prog = await getDmReadProgress(chatId, saved.id);

      broadcastToDmChatId(chatId, {
        type: "dm_chat",
        chatId,
        message: {
          id: saved.id,
          at: saved.at,
          from: ws.user.displayName,
          fromId: ws.user.id,
          text: text.slice(0, 2000),
          read: prog,
        }
      });

      const participants = await getDmParticipants(chatId);
      for (const uid of participants) {
        sendToUser(uid, { type: "dm_notice", chatId });
        sendToUser(uid, { type: "refresh_lists" });
      }
      return;
    }

    if (msg.type === "dm_read" && typeof msg.chatId === "number" && typeof msg.lastReadMessageId === "number") {
      const chatId = Math.floor(msg.chatId);
      const lastReadMessageId = Math.floor(msg.lastReadMessageId);

      const allowed = await canAccessDmChat(ws.user.id, chatId);
      if (!allowed) return;

      await upsertDmRead(chatId, ws.user.id, lastReadMessageId);
      const prog = await getDmReadProgress(chatId, lastReadMessageId);

      broadcastToDmChatId(chatId, { type: "dm_read_progress", chatId, messageId: lastReadMessageId, read: prog });
      sendToUser(ws.user.id, { type: "refresh_lists" });
      return;
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

/* =========================
   START: Render-friendly
========================= */
const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on :${PORT}`);
});

(async () => {
  try {
    await migrate();
    console.log("Migrations OK");
  } catch (e) {
    console.error("Migration failed:", e);
  }
})();
