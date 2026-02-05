import "dotenv/config";
import express from "express";
import http from "http";
import { WebSocketServer } from "ws";
import pg from "pg";
import bcrypt from "bcryptjs";
import cookie from "cookie";
import crypto from "crypto";

const { Pool } = pg;

const app = express();
app.use(express.json({ limit: process.env.JSON_LIMIT || "50mb" }));
app.use(express.urlencoded({ extended: true, limit: process.env.JSON_LIMIT || "50mb" }));
app.use(express.static("public"));
app.get("/health", (_req, res) => res.json({ ok: true }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

const MAX_ATTACHMENT_BYTES = Number(process.env.MAX_ATTACHMENT_BYTES || 2 * 1024 * 1024);


// cached settings
let _maxAttachmentCache = { value: MAX_ATTACHMENT_BYTES, at: 0 };
async function getMaxAttachmentBytes() {
  const ttlMs = 30_000;
  const now = Date.now();
  if (now - _maxAttachmentCache.at < ttlMs) return _maxAttachmentCache.value;

  try {
    const row = await queryOne(`SELECT value FROM app_settings WHERE key='max_attachment_bytes'`, []);
    const v = row ? Number(row.value) : MAX_ATTACHMENT_BYTES;
    const val = Number.isFinite(v) && v > 0 ? v : MAX_ATTACHMENT_BYTES;
    _maxAttachmentCache = { value: val, at: now };
    return val;
  } catch {
    return MAX_ATTACHMENT_BYTES;
  }
}

let SUPERADMIN_USER_ID = null;
const SUPERADMIN_EMAIL = (process.env.SUPERADMIN_EMAIL || "").trim().toLowerCase();
const ALLOWED_EMAIL_DOMAINS = (process.env.ALLOWED_EMAIL_DOMAINS || "").trim().toLowerCase();
// пример: "company.com" или "company.com,subsidiary.org"
const ALLOWED_EMAIL_DOMAIN_LIST = ALLOWED_EMAIL_DOMAINS
  ? ALLOWED_EMAIL_DOMAINS.split(",").map(s => s.trim()).filter(Boolean)
  : [];

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
function emailDomainAllowed(email) {
  if (!ALLOWED_EMAIL_DOMAIN_LIST.length) return true;
  const at = String(email || "").lastIndexOf("@");
  if (at < 0) return false;
  const domain = String(email).slice(at + 1).toLowerCase();
  return ALLOWED_EMAIL_DOMAIN_LIST.includes(domain);
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

async function refreshSuperadminUserId() {
  // SUPERADMIN_EMAIL is optional; if not set, do nothing
  if (!SUPERADMIN_EMAIL) { SUPERADMIN_USER_ID = null; return; }
  try {
    const row = await queryOne(
      "SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1",
      [SUPERADMIN_EMAIL]
    );
    SUPERADMIN_USER_ID = row ? Number(row.id) : null;
    if (SUPERADMIN_USER_ID) {
      // Keep superadmin always online for UI lists
      onlineCounts.set(SUPERADMIN_USER_ID, 1);
    }
  } catch {
    // ignore
  }
}


/* =========================
   Online presence + sockets map
========================= */
const onlineCounts = new Map(); // userId -> count
const userSockets = new Map();  // userId -> Set<ws>

function setOnline(userId, delta) {
  
if (SUPERADMIN_USER_ID && Number(userId) === Number(SUPERADMIN_USER_ID)) {
  // Суперадмина вообще не трекаем в presence
  return { was: false, now: false };
}
// Always keep superadmin online
  if (SUPERADMIN_USER_ID && Number(userId) === Number(SUPERADMIN_USER_ID)) {
    onlineCounts.set(Number(SUPERADMIN_USER_ID), 1);
    return { was: true, now: true };
  }
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
  const ids = [...onlineCounts.keys()];
  return SUPERADMIN_USER_ID ? ids.filter(id => Number(id) !== Number(SUPERADMIN_USER_ID)) : ids;
}

/* =========================
   Auth & Sessions
========================= */
async function getUserBySessionToken(sessionToken) {
  if (!sessionToken) return null;

  const row = await queryOne(
    `SELECT u.id, u.email, u.display_name, u.system_role, u.created_at, u.is_active
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > NOW()`,
    [sessionToken]
  );
  if (!row) return null;
  if (row.is_active === false) return null;

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


function logForbiddenAttempt(req, required) {
  const u = req.user;
  if (!u) return;
  safeAuditLog(u.id, "FORBIDDEN_ATTEMPT", {
    at: nowIso(),
    required,
    path: req.path,
    method: req.method,
    systemRole: u.systemRole,
    isSuperadmin: Boolean(u.isSuperadmin),
  });
}

function requireOwnerOrAdmin(req, res, next) {
  const u = req.user;
  if (u.isSuperadmin) return next();
  if (u.systemRole === "OWNER" || u.systemRole === "ADMIN") return next();
  logForbiddenAttempt(req, "OWNER_OR_ADMIN");
  return fail(res, 403, "FORBIDDEN", "Not enough permissions");
}
function requireOwner(req, res, next) {
  const u = req.user;
  if (u.isSuperadmin) return next();
  if (u.systemRole === "OWNER") return next();
  logForbiddenAttempt(req, "OWNER_ONLY");
  return fail(res, 403, "FORBIDDEN", "Owner only");
}

function requireSuperadmin(req, res, next) {
  const u = req.user;
  if (u && u.isSuperadmin) return next();
  logForbiddenAttempt(req, "SUPERADMIN_ONLY");
  return fail(res, 403, "FORBIDDEN", "Superadmin only");
}

// NEW: bootstrap status (можно ли регистрировать первого пользователя без инвайта)
app.get("/api/bootstrap", async (_req, res) => {
  const row = await queryOne(`SELECT COUNT(*)::int AS c FROM users`, []);
  const count = Number(row?.c || 0);
  ok(res, { allowFirstRegistration: count === 0 });
});

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

  const ch = await queryOne(`SELECT id, is_public, deleted_at FROM channels WHERE id=$1`, [channelId]);
  if (!ch) return false;
  if (ch.deleted_at) return false;
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
      WHERE c.deleted_at IS NULL
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
      WHERE c.deleted_at IS NULL AND (c.is_public = true
         OR cua.user_id IS NOT NULL
         OR cra.role_id IS NOT NULL)
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


async function validateInviteForRegister(inviteToken) {
  const token = String(inviteToken || "").trim();
  if (!token) return { ok: false, code: "INVITE_REQUIRED", message: "Нужен инвайт-код" };

  const inv = await queryOne(
    `SELECT id, token, expires_at, max_uses, used_count, is_revoked
     FROM invites
     WHERE token=$1`,
    [token]
  );
  if (!inv) return { ok: false, code: "INVITE_INVALID", message: "Инвайт недействителен" };
  if (inv.is_revoked) return { ok: false, code: "INVITE_REVOKED", message: "Инвайт отозван" };
  if (inv.expires_at && new Date(inv.expires_at).getTime() < Date.now()) {
    return { ok: false, code: "INVITE_EXPIRED", message: "Инвайт истёк" };
  }
  if (Number(inv.used_count) >= Number(inv.max_uses)) {
    return { ok: false, code: "INVITE_USED_UP", message: "Инвайт уже использован" };
  }
  return { ok: true, inviteId: Number(inv.id), token: inv.token };
}

async function consumeInvite(inviteId) {
  // инкремент с защитой от гонок
  const row = await queryOne(
    `UPDATE invites
     SET used_count = used_count + 1
     WHERE id=$1 AND is_revoked=false AND (expires_at IS NULL OR expires_at > NOW()) AND used_count < max_uses
     RETURNING id`,
    [inviteId]
  );
  return Boolean(row);
}

async function auditLog(actorUserId, action, metaObj) {
  await pool.query(
    `INSERT INTO audit_logs (actor_user_id, action, meta)
     VALUES ($1, $2, $3::jsonb)`,
    [actorUserId, action, JSON.stringify(metaObj || {})]
  );
}

async function safeAuditLog(actorUserId, action, metaObj) {
  try {
    await auditLog(actorUserId, action, metaObj);
  } catch {
    // never break request on audit failure
  }
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
  const ch = await queryOne(`SELECT id, is_public, deleted_at FROM channels WHERE id=$1`, [channelId]);
  if (!ch) return [];

  // SUPERADMIN может иметь доступ, но НЕ должен учитываться в "прочитано X/Y".
  // Поэтому здесь считаем только обычных пользователей + OWNER, которым реально положен доступ.

  // public => все пользователи (OWNER уже входит в users)
  if (ch.is_public) {
    const { rows } = await pool.query(`SELECT id FROM users ORDER BY id ASC`);
    return rows.map(r => Number(r.id));
  }

  // private => (role_access users) U (direct user access) U OWNER
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
    )
    SELECT DISTINCT id FROM (
      SELECT id FROM role_users
      UNION ALL SELECT id FROM direct_users
      UNION ALL SELECT id FROM owners
    ) t
    `,
    [channelId]
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


async function getLastDmMessageIds(chatId, limit = 30) {
  const { rows } = await pool.query(
    `SELECT id FROM dm_messages WHERE chat_id=$1 ORDER BY id DESC LIMIT $2`,
    [chatId, limit]
  );
  return rows.map(r => Number(r.id)).reverse();
}

async function getDmReadProgressBatch(chatId, messageIds) {
  if (!messageIds.length) return { total: 0, items: [] };

  const { rows: pr } = await pool.query(
    `SELECT user_a_id, user_b_id FROM dm_chats WHERE id=$1`,
    [chatId]
  );
  const a = pr[0] ? Number(pr[0].user_a_id) : 0;
  const b = pr[0] ? Number(pr[0].user_b_id) : 0;
  const participants = [a, b].filter(Boolean);
  const total = participants.length;

  const { rows } = await pool.query(
    `SELECT user_id, last_read_message_id
     FROM dm_reads
     WHERE chat_id=$1 AND user_id = ANY($2::int[])`,
    [chatId, participants]
  );

  const lastReadByUser = new Map();
  for (const rr of rows) lastReadByUser.set(Number(rr.user_id), Number(rr.last_read_message_id));

  const items = messageIds.map((mid) => {
    let readCount = 0;
    for (const uid of participants) {
      const last = lastReadByUser.get(uid) || 0;
      if (last >= mid) readCount += 1;
    }
    return { messageId: mid, readCount, total };
  });

  return { total, items };
}

async function broadcastDmReadBatch(chatId) {
  const ids = await getLastDmMessageIds(chatId, 30);
  const batch = await getDmReadProgressBatch(chatId, ids);
  broadcastToDmChatId(chatId, { type: "dm_read_progress_batch", chatId, items: batch.items });
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
            m.deleted_at, m.deleted_by_user_id, m.edited_at, m.edited_by_user_id,
            m.edited_at, m.edited_by_user_id,
            EXTRACT(EPOCH FROM m.created_at)*1000 AS at,
            u.display_name,
            u.id AS sender_id,
            a.id AS attachment_id, a.file_name AS attachment_name, a.mime AS attachment_mime, a.size_bytes AS attachment_size
     FROM dm_messages m
     JOIN users u ON u.id = m.sender_user_id
     LEFT JOIN attachments a ON a.id = m.attachment_id
     WHERE m.chat_id=$1
     ORDER BY m.id DESC
     LIMIT $2`,
    [chatId, limit]
  );

  const messages = rows.reverse().map(r => ({
    id: Number(r.id),
    text: r.text,
    deletedAt: r.deleted_at ? r.deleted_at : null,
    deletedByUserId: r.deleted_by_user_id ? Number(r.deleted_by_user_id) : null,
    editedAt: r.edited_at ? r.edited_at : null,
    editedByUserId: r.edited_by_user_id ? Number(r.edited_by_user_id) : null,
    at: Number(r.at),
    from: r.display_name,
    fromId: Number(r.sender_id),
    read: { readCount: 0, total: 0 },
    attachment: r.attachment_id ? {
      id: Number(r.attachment_id),
      name: r.attachment_name,
      mime: r.attachment_mime,
      size: Number(r.attachment_size || 0),
      url: `/api/attachments/${Number(r.attachment_id)}`,
      isImage: String(r.attachment_mime || "").startsWith("image/"),
    } : null,
  }));

  const tail = messages.slice(Math.max(0, messages.length - 50));
  for (const m of tail) {
    m.read = await getDmReadProgress(chatId, m.id);
  }

  return messages;
}

async function saveDmMessage(chatId, senderUserId, text, attachmentId) {
  const att = await assertAndBindAttachment(Number(attachmentId || 0), senderUserId, { dmChatId: chatId });

  const row = await queryOne(
    `INSERT INTO dm_messages (chat_id, sender_user_id, text, attachment_id, created_at)
     VALUES ($1,$2,$3,$4,NOW())
     RETURNING id, EXTRACT(EPOCH FROM created_at)*1000 AS at, attachment_id`,
    [chatId, senderUserId, text, att ? att.id : null]
  );
  return { id: Number(row.id), at: Number(row.at), attachment: att };
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      is_active BOOLEAN NOT NULL DEFAULT true
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
      deleted_at TIMESTAMPTZ NULL,
      deleted_by_user_id INT NULL REFERENCES users(id) ON DELETE SET NULL,
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

    -- DM (moved up)
    CREATE TABLE IF NOT EXISTS dm_chats (
      id BIGSERIAL PRIMARY KEY,
      user_a_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      user_b_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_a_id, user_b_id)
    );

    -- Attachments (moved up)
    CREATE TABLE IF NOT EXISTS attachments (
      id BIGSERIAL PRIMARY KEY,
      uploader_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      file_name TEXT NOT NULL,
      mime TEXT NOT NULL,
      size_bytes INT NOT NULL,
      data BYTEA NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      bound_channel_id INT NULL REFERENCES channels(id) ON DELETE CASCADE,
      bound_dm_chat_id BIGINT NULL REFERENCES dm_chats(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS channel_messages (
      id BIGSERIAL PRIMARY KEY,
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      sender_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      attachment_id BIGINT NULL REFERENCES attachments(id) ON DELETE SET NULL,
      deleted_at TIMESTAMPTZ NULL,
      deleted_by_user_id INT NULL REFERENCES users(id) ON DELETE SET NULL,
      edited_at TIMESTAMPTZ NULL,
      edited_by_user_id INT NULL REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS channel_reads (
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      last_read_message_id BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (channel_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS dm_messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id BIGINT NOT NULL REFERENCES dm_chats(id) ON DELETE CASCADE,
      sender_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      attachment_id BIGINT NULL REFERENCES attachments(id) ON DELETE SET NULL,
      deleted_at TIMESTAMPTZ NULL,
      deleted_by_user_id INT NULL REFERENCES users(id) ON DELETE SET NULL,
      edited_at TIMESTAMPTZ NULL,
      edited_by_user_id INT NULL REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dm_reads (
      chat_id BIGINT NOT NULL REFERENCES dm_chats(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      last_read_message_id BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (chat_id, user_id)
    );

    
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );


CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );

    
    CREATE TABLE IF NOT EXISTS invites (
      id BIGSERIAL PRIMARY KEY,
      token TEXT UNIQUE NOT NULL,
      created_by_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NULL,
      max_uses INT NOT NULL DEFAULT 1,
      used_count INT NOT NULL DEFAULT 0,
      is_revoked BOOLEAN NOT NULL DEFAULT false
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
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;`);

  await pool.query(`ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS attachment_id BIGINT NULL;`);
  await pool.query(`ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS attachment_id BIGINT NULL;`);

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'channel_messages_attachment_id_fkey'
      ) THEN
        ALTER TABLE channel_messages
          ADD CONSTRAINT channel_messages_attachment_id_fkey
          FOREIGN KEY (attachment_id) REFERENCES attachments(id)
          ON DELETE SET NULL;
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'dm_messages_attachment_id_fkey'
      ) THEN
        ALTER TABLE dm_messages
          ADD CONSTRAINT dm_messages_attachment_id_fkey
          FOREIGN KEY (attachment_id) REFERENCES attachments(id)
          ON DELETE SET NULL;
      END IF;
    END $$;
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_attachments_bound_channel ON attachments(bound_channel_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_attachments_bound_dm ON attachments(bound_dm_chat_id);`);

  await pool.query(`ALTER TABLE channels ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();`);
  await pool.query(`ALTER TABLE channels ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;`);
  await pool.query(`ALTER TABLE channels ADD COLUMN IF NOT EXISTS deleted_by_user_id INT NULL;`);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'channels_deleted_by_user_id_fkey') THEN
        ALTER TABLE channels
          ADD CONSTRAINT channels_deleted_by_user_id_fkey
          FOREIGN KEY (deleted_by_user_id) REFERENCES users(id)
          ON DELETE SET NULL;
      END IF;
    END $$;
  `);


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
  await pool.query(`ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;`);
  await pool.query(`ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS deleted_by_user_id INT NULL;`);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'channel_messages_deleted_by_user_id_fkey') THEN
        ALTER TABLE channel_messages
          ADD CONSTRAINT channel_messages_deleted_by_user_id_fkey
          FOREIGN KEY (deleted_by_user_id) REFERENCES users(id)
          ON DELETE SET NULL;
      END IF;
    END $$;
  `);

  await pool.query(`ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;`);
  await pool.query(`ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS deleted_by_user_id INT NULL;`);

  await pool.query(`ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ NULL;`);
  await pool.query(`ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS edited_by_user_id INT NULL;`);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'channel_messages_edited_by_user_id_fkey') THEN
        ALTER TABLE channel_messages
          ADD CONSTRAINT channel_messages_edited_by_user_id_fkey
          FOREIGN KEY (edited_by_user_id) REFERENCES users(id)
          ON DELETE SET NULL;
      END IF;
    END $$;
  `);

  await pool.query(`ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ NULL;`);
  await pool.query(`ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS edited_by_user_id INT NULL;`);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'dm_messages_edited_by_user_id_fkey') THEN
        ALTER TABLE dm_messages
          ADD CONSTRAINT dm_messages_edited_by_user_id_fkey
          FOREIGN KEY (edited_by_user_id) REFERENCES users(id)
          ON DELETE SET NULL;
      END IF;
    END $$;
  `);

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'dm_messages_deleted_by_user_id_fkey') THEN
        ALTER TABLE dm_messages
          ADD CONSTRAINT dm_messages_deleted_by_user_id_fkey
          FOREIGN KEY (deleted_by_user_id) REFERENCES users(id)
          ON DELETE SET NULL;
      END IF;
    END $$;
  `);

  await pool.query(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(
    `INSERT INTO app_settings (key, value) VALUES ('max_attachment_bytes', $1)
     ON CONFLICT (key) DO NOTHING`,
    [String(MAX_ATTACHMENT_BYTES)]
  );

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
  const inviteToken = String(req.body.inviteToken || "").trim();

  if (!isValidEmail(email)) return fail(res, 400, "BAD_EMAIL", "Invalid email");
  if (!emailDomainAllowed(email)) return fail(res, 400, "EMAIL_DOMAIN_NOT_ALLOWED", "Email домен не разрешён");
  if (password.length < 6) return fail(res, 400, "BAD_PASSWORD", "Password must be at least 6 chars");
  if (!positionRoleId) return fail(res, 400, "BAD_POSITION", "Choose a position");

  const existing = await queryOne(`SELECT 1 FROM users WHERE email=$1`, [email]);
  if (existing) return fail(res, 409, "EMAIL_TAKEN", "Email already registered");

  const hash = await bcrypt.hash(password, 10);

  const countRow = await queryOne(`SELECT COUNT(*)::int AS c FROM users`, []);
  const isFirst = Number(countRow?.c || 0) === 0;
  const systemRole = isFirst ? "OWNER" : "MEMBER";

  let inviteInfo = null;
  if (!isFirst) {
    const v = await validateInviteForRegister(inviteToken);
    if (!v.ok) return fail(res, 400, v.code, v.message);
    inviteInfo = v;
  }

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

  if (inviteInfo) {
    const consumed = await consumeInvite(inviteInfo.inviteId);
    if (!consumed) return fail(res, 400, "INVITE_USED_UP", "Инвайт уже использован");
    await auditLog(Number(user.id), "INVITE_USE", { inviteId: inviteInfo.inviteId, at: nowIso() });
  }

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
    `SELECT id, email, password_hash, display_name, system_role, is_active
     FROM users WHERE email=$1`,
    [email]
  );
  if (!row) return fail(res, 401, "INVALID_LOGIN", "Wrong email or password");
  if (row.is_active === false) return fail(res, 403, "USER_INACTIVE", "Пользователь деактивирован");

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
    `SELECT id, display_name, email, system_role, is_active
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
      isActive: u.is_active,
      isActive: u.is_active,
    }))
  });
});

app.post("/api/attachments", requireAuth, async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 200) || "file";
  const mime = String(req.body.mime || "application/octet-stream").trim().slice(0, 200) || "application/octet-stream";
  const dataBase64 = String(req.body.dataBase64 || "").trim();

  if (!dataBase64) return fail(res, 400, "BAD_INPUT", "dataBase64 required");

  let buf;
  try {
    buf = Buffer.from(dataBase64, "base64");
  } catch {
    return fail(res, 400, "BAD_INPUT", "bad base64");
  }
  if (!buf || !buf.length) return fail(res, 400, "BAD_INPUT", "empty file");
  const maxBytes = await getMaxAttachmentBytes();
  if (buf.length > maxBytes) return fail(res, 413, "FILE_TOO_LARGE", "Файл слишком большой");

  const row = await queryOne(
    `INSERT INTO attachments (uploader_user_id, file_name, mime, size_bytes, data)
     VALUES ($1,$2,$3,$4,$5)
     RETURNING id, file_name, mime, size_bytes, created_at`,
    [req.user.id, name, mime, buf.length, buf]
  );

  await safeAuditLog(req.user.id, "ATTACHMENT_UPLOAD", { attachmentId: Number(row.id), size: buf.length, mime, at: nowIso() });

  ok(res, {
    attachment: {
      id: Number(row.id),
      name: row.file_name,
      mime: row.mime,
      size: Number(row.size_bytes),
      url: `/api/attachments/${Number(row.id)}`,
      isImage: String(row.mime || "").startsWith("image/"),
    }
  });
});

app.get("/api/attachments/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return fail(res, 400, "BAD_INPUT", "bad attachment id");

  const a = await queryOne(
    `SELECT id, uploader_user_id, file_name, mime, size_bytes, data, bound_channel_id, bound_dm_chat_id
     FROM attachments
     WHERE id=$1`,
    [id]
  );
  if (!a) return fail(res, 404, "NOT_FOUND", "Attachment not found");

  // доступ: если не привязан — только загрузивший
  const boundChannelId = a.bound_channel_id ? Number(a.bound_channel_id) : null;
  const boundDmChatId = a.bound_dm_chat_id ? Number(a.bound_dm_chat_id) : null;

  let allowed = false;
  if (!boundChannelId && !boundDmChatId) {
    allowed = (Number(a.uploader_user_id) === req.user.id) || req.user.isSuperadmin || req.user.systemRole === "OWNER";
  } else if (boundChannelId) {
    allowed = await canAccessChannel(req.user, boundChannelId);
  } else if (boundDmChatId) {
    allowed = req.user.isSuperadmin || req.user.systemRole === "OWNER" || await canAccessDmChat(req.user.id, boundDmChatId);
  }

  if (!allowed) return fail(res, 403, "FORBIDDEN", "No access");

  const mime = a.mime || "application/octet-stream";
  res.setHeader("Content-Type", mime);
  const isImage = String(mime).startsWith("image/");
  const disp = isImage ? "inline" : "attachment";
  res.setHeader("Content-Disposition", `${disp}; filename="${String(a.file_name || "file").replace(/"/g, "")}"`);
  res.send(a.data);
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
    `SELECT id, email, display_name, system_role, is_active, created_at
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
      isActive: u.is_active,
      isActive: u.is_active,
      createdAt: u.created_at,
    })),
  });
});


app.post("/api/admin/users/:id/deactivate", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  if (!userId) return fail(res, 400, "BAD_INPUT", "bad user id");
  if (userId === req.user.id) return fail(res, 400, "BAD_INPUT", "cannot deactivate yourself");

  const row = await queryOne(`UPDATE users SET is_active=false WHERE id=$1 RETURNING id`, [userId]);
  if (!row) return fail(res, 404, "NOT_FOUND", "User not found");

  await safeAuditLog(req.user.id, "USER_DEACTIVATE", { userId, at: nowIso() });
  ok(res, {});
});

app.post("/api/admin/users/:id/activate", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  if (!userId) return fail(res, 400, "BAD_INPUT", "bad user id");

  const row = await queryOne(`UPDATE users SET is_active=true WHERE id=$1 RETURNING id`, [userId]);
  if (!row) return fail(res, 404, "NOT_FOUND", "User not found");

  await safeAuditLog(req.user.id, "USER_ACTIVATE", { userId, at: nowIso() });
  ok(res, {});
});

app.post("/api/admin/users/:id/reset_password", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  if (!userId) return fail(res, 400, "BAD_INPUT", "bad user id");

  // временный пароль (одноразово сообщить сотруднику)
  const temp = crypto.randomBytes(6).toString("base64").replace(/[^a-zA-Z0-9]/g, "").slice(0, 10);
  const hash = await bcrypt.hash(temp, 10);

  const row = await queryOne(`UPDATE users SET password_hash=$2 WHERE id=$1 RETURNING id`, [userId, hash]);
  if (!row) return fail(res, 404, "NOT_FOUND", "User not found");

  await safeAuditLog(req.user.id, "USER_RESET_PASSWORD", { userId, at: nowIso() });
  ok(res, { tempPassword: temp });
});


app.get("/api/admin/settings/attachments", requireAuth, requireSuperadmin, async (_req, res) => {
  const maxBytes = await getMaxAttachmentBytes();
  ok(res, { maxAttachmentBytes: maxBytes });
});

app.post("/api/admin/settings/attachments", requireAuth, requireSuperadmin, async (req, res) => {
  const maxAttachmentBytes = Number(req.body.maxAttachmentBytes || 0);
  if (!Number.isFinite(maxAttachmentBytes) || maxAttachmentBytes < 50_000 || maxAttachmentBytes > 50 * 1024 * 1024) {
    return fail(res, 400, "BAD_INPUT", "maxAttachmentBytes must be between 50KB and 50MB");
  }

  await pool.query(
    `INSERT INTO app_settings (key, value, updated_at)
     VALUES ('max_attachment_bytes', $1, NOW())
     ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`,
    [String(Math.floor(maxAttachmentBytes))]
  );
  _maxAttachmentCache.at = 0;

  await safeAuditLog(req.user.id, "SETTINGS_ATTACHMENTS_UPDATE", { maxAttachmentBytes: Math.floor(maxAttachmentBytes), at: nowIso() });
  ok(res, { maxAttachmentBytes: Math.floor(maxAttachmentBytes) });
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
    `SELECT id, name, is_public FROM channels WHERE deleted_at IS NULL ORDER BY name ASC LIMIT 200`
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


app.patch("/api/admin/channels/:id", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const channelId = Number(req.params.id);
  if (!channelId) return fail(res, 400, "BAD_INPUT", "bad channel id");

  const ch = await queryOne(`SELECT id, name, is_public, deleted_at FROM channels WHERE id=$1`, [channelId]);
  if (!ch || ch.deleted_at) return fail(res, 404, "NOT_FOUND", "Channel not found");

  const nextNameRaw = req.body.name !== undefined ? String(req.body.name || "") : null;
  const nextName = nextNameRaw === null ? null : normalizeChannelName(nextNameRaw);
  const nextIsPublic = (req.body.isPublic === undefined) ? null : Boolean(req.body.isPublic);

  if (nextNameRaw !== null && !nextName) return fail(res, 400, "BAD_INPUT", "Bad channel name");

  try {
    const upd = await queryOne(
      `UPDATE channels
       SET name = COALESCE($2, name),
           is_public = COALESCE($3, is_public)
       WHERE id=$1
       RETURNING id, name, is_public`,
      [channelId, nextName, nextIsPublic]
    );

    if (nextName && nextName !== ch.name) {
      await auditLog(req.user.id, "CHANNEL_RENAME", { channelId, oldName: ch.name, newName: upd.name, at: nowIso() });
    }
    if (nextIsPublic !== null && Boolean(nextIsPublic) !== Boolean(ch.is_public)) {
      await auditLog(req.user.id, "CHANNEL_PRIVACY_CHANGE", { channelId, from: ch.is_public ? "public" : "private", to: upd.is_public ? "public" : "private", at: nowIso() });
    }

    broadcastAll({ type: "channel_updated", channelId });
    broadcastAll({ type: "refresh_lists" });

    ok(res, { channel: { id: Number(upd.id), name: upd.name, isPublic: upd.is_public } });
  } catch (e) {
    if (String(e.code) === "23505") return fail(res, 409, "CHANNEL_EXISTS", "Channel name already exists");
    console.error(e);
    return fail(res, 500, "SERVER_ERROR", "Failed to update channel");
  }
});

app.delete("/api/admin/channels/:id", requireAuth, requireOwner, async (req, res) => {
  const channelId = Number(req.params.id);
  if (!channelId) return fail(res, 400, "BAD_INPUT", "bad channel id");

  const ch = await queryOne(`SELECT id, name, deleted_at FROM channels WHERE id=$1`, [channelId]);
  if (!ch || ch.deleted_at) return fail(res, 404, "NOT_FOUND", "Channel not found");

  await pool.query(
    `UPDATE channels
     SET deleted_at = NOW(), deleted_by_user_id = $2
     WHERE id=$1`,
    [channelId, req.user.id]
  );

  await auditLog(req.user.id, "CHANNEL_DELETE", { channelId, name: ch.name, at: nowIso() });

  broadcastAll({ type: "channel_deleted", channelId });
  broadcastAll({ type: "refresh_lists" });

  ok(res, {});
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


app.post("/api/admin/invites", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const maxUses = Math.max(1, Math.min(1000, Number(req.body.maxUses || 1)));
  const expiresInHours = Number(req.body.expiresInHours || 0);
  const token = crypto.randomBytes(16).toString("hex");

  let expiresAt = null;
  if (expiresInHours && Number.isFinite(expiresInHours) && expiresInHours > 0) {
    expiresAt = new Date(Date.now() + expiresInHours * 3600 * 1000).toISOString();
  }

  const row = await queryOne(
    `INSERT INTO invites (token, created_by_user_id, expires_at, max_uses)
     VALUES ($1,$2,$3,$4)
     RETURNING id, token, created_at, expires_at, max_uses, used_count, is_revoked`,
    [token, req.user.id, expiresAt, maxUses]
  );

  await auditLog(req.user.id, "INVITE_CREATE", { inviteId: Number(row.id), maxUses, expiresAt, at: nowIso() });
  ok(res, { invite: {
    id: Number(row.id),
    token: row.token,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    maxUses: Number(row.max_uses),
    usedCount: Number(row.used_count),
    isRevoked: Boolean(row.is_revoked),
  }});
});

app.get("/api/admin/invites", requireAuth, requireOwnerOrAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT i.id, i.token, i.created_at, i.expires_at, i.max_uses, i.used_count, i.is_revoked,
            u.email AS created_by_email, u.display_name AS created_by_name
     FROM invites i
     JOIN users u ON u.id = i.created_by_user_id
     ORDER BY i.id DESC
     LIMIT 200`
  );

  ok(res, { invites: rows.map(r => ({
    id: Number(r.id),
    token: r.token,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    maxUses: Number(r.max_uses),
    usedCount: Number(r.used_count),
    isRevoked: Boolean(r.is_revoked),
    createdBy: { email: r.created_by_email, displayName: r.created_by_name }
  }))});
});

app.delete("/api/admin/invites/:id", requireAuth, requireOwnerOrAdmin, async (req, res) => {
  const inviteId = Number(req.params.id);
  if (!inviteId) return fail(res, 400, "BAD_INPUT", "bad invite id");

  const row = await queryOne(
    `UPDATE invites SET is_revoked=true WHERE id=$1 RETURNING id`,
    [inviteId]
  );
  if (!row) return fail(res, 404, "NOT_FOUND", "Invite not found");

  await auditLog(req.user.id, "INVITE_REVOKE", { inviteId, at: nowIso() });
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
            m.deleted_at, m.deleted_by_user_id, m.edited_at, m.edited_by_user_id,
            m.edited_at, m.edited_by_user_id,
            u.id AS sender_id, u.display_name AS sender_name, u.email AS sender_email
     FROM dm_messages m
     JOIN users u ON u.id = m.sender_user_id
     LEFT JOIN attachments a ON a.id = m.attachment_id
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
    deletedAt: r.deleted_at ? r.deleted_at : null,
    deletedByUserId: r.deleted_by_user_id ? Number(r.deleted_by_user_id) : null,
    editedAt: r.edited_at ? r.edited_at : null,
    editedByUserId: r.edited_by_user_id ? Number(r.edited_by_user_id) : null,
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
            m.deleted_at, m.deleted_by_user_id, m.edited_at, m.edited_by_user_id,
            m.edited_at, m.edited_by_user_id,
            u.display_name, u.id AS sender_id,
            a.id AS attachment_id, a.file_name AS attachment_name, a.mime AS attachment_mime, a.size_bytes AS attachment_size
     FROM channel_messages m
     JOIN users u ON u.id = m.sender_user_id
     LEFT JOIN attachments a ON a.id = m.attachment_id
     WHERE m.channel_id=$1
     ORDER BY m.id DESC
     LIMIT $2`,
    [channelId, limit]
  );

  const messages = rows.reverse().map(r => ({
    id: Number(r.id),
    text: r.text,
    deletedAt: r.deleted_at ? r.deleted_at : null,
    deletedByUserId: r.deleted_by_user_id ? Number(r.deleted_by_user_id) : null,
    editedAt: r.edited_at ? r.edited_at : null,
    editedByUserId: r.edited_by_user_id ? Number(r.edited_by_user_id) : null,
    at: Number(r.at),
    from: r.display_name,
    fromId: Number(r.sender_id),
    read: { readCount: 0, total: 0 },
    attachment: r.attachment_id ? {
      id: Number(r.attachment_id),
      name: r.attachment_name,
      mime: r.attachment_mime,
      size: Number(r.attachment_size || 0),
      url: `/api/attachments/${Number(r.attachment_id)}`,
      isImage: String(r.attachment_mime || "").startsWith("image/"),
    } : null,
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


async function assertAndBindAttachment(attachmentId, uploaderUserId, bind) {
  if (!attachmentId) return null;
  const a = await queryOne(
    `SELECT id, uploader_user_id, bound_channel_id, bound_dm_chat_id, file_name, mime, size_bytes
     FROM attachments
     WHERE id=$1`,
    [attachmentId]
  );
  if (!a) return null;
  if (Number(a.uploader_user_id) !== Number(uploaderUserId)) return null;
  if (a.bound_channel_id || a.bound_dm_chat_id) return null;

  if (bind.channelId) {
    await pool.query(`UPDATE attachments SET bound_channel_id=$2 WHERE id=$1`, [attachmentId, bind.channelId]);
  } else if (bind.dmChatId) {
    await pool.query(`UPDATE attachments SET bound_dm_chat_id=$2 WHERE id=$1`, [attachmentId, bind.dmChatId]);
  }
  return {
    id: Number(a.id),
    name: a.file_name,
    mime: a.mime,
    size: Number(a.size_bytes),
    url: `/api/attachments/${Number(a.id)}`,
    isImage: String(a.mime || "").startsWith("image/"),
  };
}

async function saveChannelMessage(channelId, senderUserId, text, attachmentId) {
  // привязка вложения (если есть)
  const att = await assertAndBindAttachment(Number(attachmentId || 0), senderUserId, { channelId });

  const row = await queryOne(
    `INSERT INTO channel_messages (channel_id, sender_user_id, text, attachment_id)
     VALUES ($1,$2,$3,$4)
     RETURNING id, EXTRACT(EPOCH FROM created_at)*1000 AS at, attachment_id`,
    [channelId, senderUserId, text, att ? att.id : null]
  );
  return { id: Number(row.id), at: Number(row.at), attachment: att };
}

function broadcastToChannelId(channelId, obj) {
  const payload = JSON.stringify(obj);
  for (const c of wss.clients) {
    if (c.readyState === 1 && c.channelId === channelId) c.send(payload);
  }
}

async function softDeleteChannelMessage(messageId, actorUserId) {
  const row = await queryOne(
    `UPDATE channel_messages
     SET deleted_at = NOW(), deleted_by_user_id = $2
     WHERE id=$1 AND sender_user_id=$2 AND deleted_at IS NULL
     RETURNING id, channel_id`,
    [messageId, actorUserId]
  );
  return row ? { id: Number(row.id), channelId: Number(row.channel_id) } : null;
}

async function softDeleteDmMessage(messageId, actorUserId) {
  const row = await queryOne(
    `UPDATE dm_messages
     SET deleted_at = NOW(), deleted_by_user_id = $2
     WHERE id=$1 AND sender_user_id=$2 AND deleted_at IS NULL
     RETURNING id, chat_id`,
    [messageId, actorUserId]
  );
  return row ? { id: Number(row.id), chatId: Number(row.chat_id) } : null;
}


async function softEditChannelMessage(messageId, actorUserId, newText) {
  const row = await queryOne(
    `UPDATE channel_messages
     SET text = $3, edited_at = NOW(), edited_by_user_id = $2
     WHERE id=$1 AND sender_user_id=$2 AND deleted_at IS NULL
     RETURNING id, channel_id, text, EXTRACT(EPOCH FROM edited_at)*1000 AS edited_ms`,
    [messageId, actorUserId, newText]
  );
  return row ? { id: Number(row.id), channelId: Number(row.channel_id), text: row.text, editedAtMs: Number(row.edited_ms) } : null;
}

async function softEditDmMessage(messageId, actorUserId, newText) {
  const row = await queryOne(
    `UPDATE dm_messages
     SET text = $3, edited_at = NOW(), edited_by_user_id = $2
     WHERE id=$1 AND sender_user_id=$2 AND deleted_at IS NULL
     RETURNING id, chat_id, text, EXTRACT(EPOCH FROM edited_at)*1000 AS edited_ms`,
    [messageId, actorUserId, newText]
  );
  return row ? { id: Number(row.id), chatId: Number(row.chat_id), text: row.text, editedAtMs: Number(row.edited_ms) } : null;
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

      const attachmentId = Number(msg.attachmentId || 0);
      const saved = await saveChannelMessage(ws.channelId, ws.user.id, text.slice(0, 2000), attachmentId);

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
          attachment: saved.attachment || null,
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
        await broadcastDmReadBatch(chatId);

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

      const attachmentId = Number(msg.attachmentId || 0);
      const saved = await saveDmMessage(chatId, ws.user.id, text.slice(0, 2000), attachmentId);
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
          attachment: saved.attachment || null,
          read: prog,
        }
      });
      await broadcastDmReadBatch(chatId);


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
      await broadcastDmReadBatch(chatId);
      sendToUser(ws.user.id, { type: "refresh_lists" });
      return;
    }

    /* ===== Delete (soft) ===== */
    if (msg.type === "delete" && typeof msg.messageId === "number") {
      const messageId = Math.floor(msg.messageId);
      if (!ws.channelId) return;

      const deleted = await softDeleteChannelMessage(messageId, ws.user.id);
      if (!deleted) return;

      await safeAuditLog(ws.user.id, "MESSAGE_DELETE", { messageId, channelId: deleted.channelId, at: nowIso() });
      broadcastToChannelId(deleted.channelId, { type: "message_deleted", channelId: deleted.channelId, messageId });
      broadcastAll({ type: "channel_notice", channelId: deleted.channelId });
      return;
    }

    if (msg.type === "dm_delete" && typeof msg.messageId === "number") {
      const messageId = Math.floor(msg.messageId);
      if (!ws.dmChatId) return;

      const deleted = await softDeleteDmMessage(messageId, ws.user.id);
      if (!deleted) return;

      await safeAuditLog(ws.user.id, "DM_MESSAGE_DELETE", { messageId, chatId: deleted.chatId, at: nowIso() });
      broadcastToDmChatId(deleted.chatId, { type: "dm_message_deleted", chatId: deleted.chatId, messageId });

      const participants = await getDmParticipants(deleted.chatId);
      for (const uid of participants) {
        sendToUser(uid, { type: "dm_notice", chatId: deleted.chatId });
        sendToUser(uid, { type: "refresh_lists" });
      }
      return;
    }

    /* ===== Edit ===== */
    if (msg.type === "edit" && typeof msg.messageId === "number" && typeof msg.text === "string") {
      const messageId = Math.floor(msg.messageId);
      const newText = msg.text.trim().slice(0, 2000);
      if (!newText) return;
      if (!ws.channelId) return;

      const edited = await softEditChannelMessage(messageId, ws.user.id, newText);
      if (!edited) return;

      await safeAuditLog(ws.user.id, "MESSAGE_EDIT", { messageId, channelId: edited.channelId, at: nowIso() });

      broadcastToChannelId(edited.channelId, {
        type: "message_edited",
        channelId: edited.channelId,
        messageId,
        text: edited.text,
        editedAt: edited.editedAtMs
      });
      broadcastAll({ type: "channel_notice", channelId: edited.channelId });
      return;
    }

    if (msg.type === "dm_edit" && typeof msg.messageId === "number" && typeof msg.text === "string") {
      const messageId = Math.floor(msg.messageId);
      const newText = msg.text.trim().slice(0, 2000);
      if (!newText) return;
      if (!ws.dmChatId) return;

      const edited = await softEditDmMessage(messageId, ws.user.id, newText);
      if (!edited) return;

      await safeAuditLog(ws.user.id, "DM_MESSAGE_EDIT", { messageId, chatId: edited.chatId, at: nowIso() });

      broadcastToDmChatId(edited.chatId, {
        type: "dm_message_edited",
        chatId: edited.chatId,
        messageId,
        text: edited.text,
        editedAt: edited.editedAtMs
      });

      const participants = await getDmParticipants(edited.chatId);
      for (const uid of participants) {
        sendToUser(uid, { type: "dm_notice", chatId: edited.chatId });
        sendToUser(uid, { type: "refresh_lists" });
      }
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
    await refreshSuperadminUserId();
    setInterval(refreshSuperadminUserId, 60 * 1000).unref?.();
    console.log("Migrations OK");
  } catch (e) {
    console.error("Migration failed:", e);
  }
})();
