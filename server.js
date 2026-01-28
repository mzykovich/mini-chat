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
   Roles & Access
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

async function listAccessibleChannels(user) {
  if (user.isSuperadmin || user.systemRole === "OWNER") {
    const { rows } = await pool.query(
      `SELECT id, name, is_public FROM channels ORDER BY name ASC LIMIT 200`
    );
    return rows.map((r) => ({ id: Number(r.id), name: r.name, isPublic: r.is_public }));
  }

  const roleIds = await getUserCustomRoleIds(user.id);

  const { rows } = await pool.query(
    `
    SELECT DISTINCT c.id, c.name, c.is_public
    FROM channels c
    LEFT JOIN channel_user_access cua
      ON cua.channel_id = c.id AND cua.user_id = $1
    LEFT JOIN channel_role_access cra
      ON cra.channel_id = c.id AND (cra.role_id = ANY($2::int[]) OR $2::int[] IS NULL)
    WHERE c.is_public = true
       OR cua.user_id IS NOT NULL
       OR cra.role_id IS NOT NULL
    ORDER BY c.name ASC
    LIMIT 200
    `,
    [user.id, roleIds.length ? roleIds : null]
  );

  return rows.map((r) => ({ id: Number(r.id), name: r.name, isPublic: r.is_public }));
}

async function auditLog(actorUserId, action, metaObj) {
  await pool.query(
    `INSERT INTO audit_logs (actor_user_id, action, meta)
     VALUES ($1, $2, $3::jsonb)`,
    [actorUserId, action, JSON.stringify(metaObj || {})]
  );
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
      system_role TEXT NOT NULL DEFAULT 'MEMBER', -- MEMBER|ADMIN|OWNER
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS roles (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,          -- slug
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

  // Upgrade older DBs safely
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
  const channels = await listAccessibleChannels(req.user);
  ok(res, { channels });
});

/* ===== Admin endpoints ===== */

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

// NEW: roles of a user
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

  const target = await queryOne(`SELECT id, system_role FROM users WHERE id=$1`, [userId]);
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

// NEW: remove role from user
app.delete("/api/admin/users/:id/roles/:roleId", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  const roleId = Number(req.params.roleId);
  if (!userId || !roleId) return fail(res, 400, "BAD_INPUT", "bad ids");

  await pool.query(
    `DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`,
    [userId, roleId]
  );

  await auditLog(req.user.id, "USER_ROLE_REMOVE", { userId, roleId, at: nowIso() });
  ok(res, {});
});

// NEW: list ALL channels for admin (so access editing works reliably)
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

// NEW: get current access for channel
app.get("/api/admin/channels/:id/access", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const channelId = Number(req.params.id);
  const ch = await queryOne(`SELECT id FROM channels WHERE id=$1`, [channelId]);
  if (!ch) return fail(res, 404, "NOT_FOUND", "Channel not found");

  const r = await pool.query(
    `SELECT role_id FROM channel_role_access WHERE channel_id=$1`,
    [channelId]
  );
  const u = await pool.query(
    `SELECT user_id FROM channel_user_access WHERE channel_id=$1`,
    [channelId]
  );

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

app.post("/api/owner/transfer", requireAuth, requireOwner, async (req, res) => {
  const newOwnerId = Number(req.body.userId || 0);
  if (!newOwnerId) return fail(res, 400, "BAD_INPUT", "userId required");

  const target = await queryOne(`SELECT id FROM users WHERE id=$1`, [newOwnerId]);
  if (!target) return fail(res, 404, "NOT_FOUND", "User not found");

  await pool.query(`UPDATE users SET system_role='ADMIN' WHERE id=$1`, [req.user.id]);
  await pool.query(`UPDATE users SET system_role='OWNER' WHERE id=$1`, [newOwnerId]);

  await auditLog(req.user.id, "OWNER_TRANSFER", { toUserId: newOwnerId, at: nowIso() });
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

/* =========================
   WebSocket (auth + channels)
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
  const channels = await listAccessibleChannels(ws.user);
  wsSend(ws, { type: "init", me: ws.user, channels });
}

async function loadChannelHistory(channelId, limit = 200) {
  const { rows } = await pool.query(
    `SELECT m.id, m.text, EXTRACT(EPOCH FROM m.created_at)*1000 AS at,
            u.display_name
     FROM channel_messages m
     JOIN users u ON u.id = m.sender_user_id
     WHERE m.channel_id=$1
     ORDER BY m.id DESC
     LIMIT $2`,
    [channelId, limit]
  );
  return rows.reverse().map((r) => ({
    id: Number(r.id),
    text: r.text,
    at: Number(r.at),
    from: r.display_name,
  }));
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

wss.on("connection", async (ws, req) => {
  const user = await wsGetUserFromReq(req);
  if (!user) {
    ws.close(4401, "unauthorized");
    return;
  }

  ws.user = user;
  ws.channelId = null;
  ws.isAlive = true;

  ws.on("pong", () => (ws.isAlive = true));
  await wsSendInit(ws);

  ws.on("message", async (buf) => {
    let msg;
    try { msg = JSON.parse(buf.toString("utf8")); } catch { return; }

    if (msg.type === "join" && typeof msg.channelId === "number") {
      const channelId = Math.floor(msg.channelId);
      const allowed = await canAccessChannel(ws.user, channelId);
      if (!allowed) {
        wsSend(ws, { type: "error", code: "NO_ACCESS", message: "No access to channel" });
        return;
      }
      ws.channelId = channelId;
      wsSend(ws, { type: "joined", channelId });
      wsSend(ws, { type: "history", channelId, messages: await loadChannelHistory(channelId) });
      return;
    }

    if (msg.type === "chat" && typeof msg.text === "string") {
      const text = msg.text.trim();
      if (!text) return;
      if (!ws.channelId) return;

      const allowed = await canAccessChannel(ws.user, ws.channelId);
      if (!allowed) {
        wsSend(ws, { type: "error", code: "NO_ACCESS", message: "No access to channel" });
        return;
      }

      const saved = await saveChannelMessage(ws.channelId, ws.user.id, text.slice(0, 2000));
      const message = { id: saved.id, at: saved.at, from: ws.user.displayName, text: text.slice(0, 2000) };

      broadcastToChannelId(ws.channelId, { type: "chat", channelId: ws.channelId, message });
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

const PORT = process.env.PORT || 3000;

(async () => {
  await migrate();
  server.listen(PORT, () => console.log(`Listening on :${PORT}`));
})();
