// server/server.js — v3.4
// Only Market: RuKassa deposits, admin deal tools, chat images, public config
// Node 18+ (global fetch). If Node <18, install node-fetch and import it.

import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import { nanoid } from "nanoid";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config({ path: path.join(path.dirname(fileURLToPath(import.meta.url)), "..", ".env") });
import Stripe from "stripe";
import { v4 as uuidv4 } from "uuid";

const STRIPE = process.env.STRIPE_SECRET ? new Stripe(process.env.STRIPE_SECRET) : null;
const STRIPE_CURRENCY = process.env.STRIPE_CURRENCY || "USD";
const STRIPE_SUCCESS_URL = process.env.STRIPE_SUCCESS_URL || "https://example.com/success";
const STRIPE_CANCEL_URL  = process.env.STRIPE_CANCEL_URL  || "https://example.com/cancel";
const STRIPE_MARKUP = Number(process.env.STRIPE_MARKUP ?? 0.7);
const STRIPE_TAX    = Number(process.env.STRIPE_TAX ?? 0.5);
const PARADISE_API = process.env.PARADISE_API || 'https://p2paradise.net/api';
const PARADISE_MERCHANT_ID = process.env.PARADISE_MERCHANT_ID;
const PARADISE_SECRET_KEY = process.env.PARADISE_SECRET_KEY;

if (!PARADISE_MERCHANT_ID || !PARADISE_SECRET_KEY) {
  console.warn('⚠️ Paradise credentials are not set in env');
}


const RUKASSA_SHOP_ID = Number(process.env.RUKASSA_SHOP_ID || 0);
const RUKASSA_TOKEN = process.env.RUKASSA_TOKEN || "";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("trust proxy", true); // корректный req.ip за прокси

app.use(express.json({ limit: "6mb" }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: "6mb" })); // for callback x-www-form-urlencoded
app.use(express.static(path.join(__dirname, "..", "public")));

const dataDir = path.join(__dirname, "data");
const mediaDir = path.join(dataDir, "media");
for (const d of [dataDir, mediaDir, path.join(dataDir, "backups")]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

/* ---------- JSON utils ---------- */

function readJSON(name, fallback) {
  const f = path.join(dataDir, name);
  if (!fs.existsSync(f)) {
    if (typeof fallback !== "undefined") {
      fs.writeFileSync(f, JSON.stringify(fallback, null, 2));
      return fallback;
    }
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(f, "utf8") || "null");
  } catch {
    return fallback ?? null;
  }
}
function writeJSON(name, obj) {
  const f = path.join(dataDir, name);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  try {
    fs.writeFileSync(
      path.join(dataDir, "backups", name + "." + stamp + ".bak"),
      JSON.stringify(obj, null, 2)
    );
  } catch {}
  fs.writeFileSync(f, JSON.stringify(obj, null, 2));
}
// --- OTP helpers (Email codes) ---
function readOTP(){ return readJSON("otp.json", {}); }
function writeOTP(o){ writeJSON("otp.json", o || {}); }
function genCode(){ return String(Math.floor(100000 + Math.random()*900000)); }


function read2FA(){ return readJSON("twofa.json", {}); }
function write2FA(o){ writeJSON("twofa.json", o||{}); }

// --- Telegram notify helpers ---
function readNotify(){ return readJSON("notify.json", {}); }
function readTgOutbox(){ return readJSON("tg_outbox.json", []); }
function writeTgOutbox(arr){ writeJSON("tg_outbox.json", Array.isArray(arr)?arr:[]); }

// Отправить в TG по userId (если привязан и включён)
function tgOutboxPushByUser(userId, text){
  const notify = readNotify();
  const tg = notify?.[userId]?.telegram || {};
  if(!tg.linked || !tg.enabled || !tg.chatId) return false;
  const box = readTgOutbox();
  box.push({ chatId: String(tg.chatId), text: String(text).slice(0, 4096) });
  writeTgOutbox(box);
  return true;
}

// --- Telegram codes / notify ---
function readCodes(){ return readJSON("tg_codes.json", {}); }
function writeCodes(obj){ writeJSON("tg_codes.json", obj); }
function writeNotify(obj){ writeJSON("notify.json", obj); }

const TELEGRAM_CODE_TTL_SEC = 10 * 60; // 10 минут

function readSupportTasks(){ return readJSON('support_tasks.json', {}); }
function writeSupportTasks(o){ writeJSON('support_tasks.json', o||{}); }
function createSupportTask(user, payload){
  const tasks = readSupportTasks();
  const id = 't_' + nanoid(8);
  tasks[id] = {
    id, status:'open',
    createdBy: user?.id || null,
    assignedTo: null,
    payload: payload || {},
    createdAt: now(), updatedAt: now()
  };
  writeSupportTasks(tasks);
  return tasks[id];
}

/* ---------- helpers ---------- */
const now = () => Date.now();
const isSuperNick = (nick) => (nick || "").toLowerCase() === "mimimitya";
// старая версия:
// const hashPw = (p) => "sha256$" + Buffer.from(String(p)).toString("base64");
// const checkPw = (p, h) => hashPw(p) === h;

function hashPwLegacy(p){ return "sha256$" + Buffer.from(String(p)).toString("base64"); }
function checkLegacy(p, h){ return h && h.startsWith('sha256$') && hashPwLegacy(p)===h; }

// scrypt (Node 18) — синхронно и коротко
function hashPw(p){
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(p), salt, 64, { N: 16384, r: 8, p: 1 });
  return "scrypt$" + salt.toString('hex') + "$" + key.toString('hex');
}
function checkPw(p, stored){
  if(!stored) return false;
  if(stored.startsWith('scrypt$')){
    const [,saltHex, keyHex] = stored.split('$');
    const salt = Buffer.from(saltHex,'hex');
    const key = crypto.scryptSync(String(p), salt, 64, { N: 16384, r: 8, p: 1 });
    return crypto.timingSafeEqual(Buffer.from(keyHex,'hex'), key);
  }
  // fallback на легаси (чтобы старые учётки работали)
  return checkLegacy(p, stored);
}

const isAdminUser = (u) =>
  !!u &&
  ((u.roles || []).includes("admin") ||
    (u.roles || []).includes("support") ||
    isSuperNick(u.nickname));

// --- Email (AWS SES v2, официальный SDK) ---
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";

const SES_REGION = process.env.AWS_SES_REGION || process.env.AWS_REGION || "eu-north-1";
const SES_FROM   = process.env.AWS_SES_FROM || "no-reply@example.com";
const AWS_K      = process.env.AWS_ACCESS_KEY_ID || "";
const AWS_S      = process.env.AWS_SECRET_ACCESS_KEY || "";

// создаём клиент только если есть ключи
const sesClient = (AWS_K && AWS_S)
  ? new SESv2Client({
      region: SES_REGION,
      credentials: { accessKeyId: AWS_K, secretAccessKey: AWS_S }
    })
  : null;

// единая функция отправки
async function sesSendEmail(to, subject, text = "", html = "") {
  if (!sesClient) {
    // fallback: складываем в outbox, чтобы не терять письма на деве
    try {
      const f = path.join(dataDir, "mail_outbox.json");
      let arr = [];
      if (fs.existsSync(f)) try { arr = JSON.parse(fs.readFileSync(f, "utf8") || "[]"); } catch {}
      arr.push({ id: "em_"+nanoid(8), to, subject, text, html, ts: Date.now() });
      fs.writeFileSync(f, JSON.stringify(arr, null, 2));
   } catch (e) {
  console.error("SES ERROR", {
    name: e?.name,
    message: e?.message,
    code: e?.Code,
    status: e?.$metadata?.httpStatusCode,
    requestId: e?.$metadata?.requestId
  });
  return { error: e?.name || "SES_ERROR", detail: e?.message || String(e) };
}

    return { queued: true, reason: "NO_AWS_KEYS" };
  }

  const params = {
    FromEmailAddress:AWS_SES_FROM,                            // ВАЖНО: чистый e-mail
    Destination: { ToAddresses: Array.isArray(to) ? to : [to] },
    Content: {
      Simple: {
        Subject: { Data: subject, Charset: "UTF-8" },
        Body: {
          Text: { Data: text || "", Charset: "UTF-8" },
          ...(html ? { Html: { Data: html, Charset: "UTF-8" } } : {})
        }
      }
    }
    // ConfigurationSetName: "OptionalSetName", // если используешь конфиг-сет
  };

  try {
    const resp = await sesClient.send(new SendEmailCommand(params));
    return { ok: true, messageId: resp?.MessageId || null };
  } catch (e) {
    // тут будет точная причина: Sandbox, From не верифицирован, и т.п.
    console.warn("SES send error:", {
      name: e?.name, code: e?.Code, message: e?.message,
      http: e?.$metadata?.httpStatusCode, region: SES_REGION
    });
    return { error: e?.name || "SES_ERROR", detail: e?.message || String(e) };
  }
}
app.post("/api/dev/test-mail", async (req, res) => {
  const to = (req.body?.to || process.env.AWS_SES_FROM).trim();
  const r = await sesSendEmail(
    to,
    "SES test",
    "Hello from Only Market",
    "<b>Hello from Only Market</b>"
  );
  res.json(r);
});
async // =============== PARADISE (p2paradise) ===============
// Используется на фронте: /api/pay/paradise/*
// ВАЖНО: этот блок должен быть валидным JS (без "..." плейсхолдеров).

async function paradiseRequest(pathname, options = {}) {
  const base = String(PARADISE_API || '').replace(/\/$/, '');
  const url = base + pathname;

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      'merchant-id': String(PARADISE_MERCHANT_ID || ''),
      'merchant-secret-key': String(PARADISE_SECRET_KEY || ''),
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const text = await res.text().catch(() => '');
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { payload = text; }

  if (!res.ok) {
    const msg = typeof payload === 'string' ? payload : JSON.stringify(payload);
    throw new Error(`Paradise ${pathname} error ${res.status}: ${msg}`);
  }
  return payload;
}

// Создание платежа
async function paradiseCreatePayment({ amountRub, customerId, ip, description, metadata, paymentMethod, returnUrl }) {
  const amount = Math.round(Number(amountRub) * 100); // RUB → копейки
  if (!Number.isFinite(amount) || amount <= 0) throw new Error('Invalid amount');

  const body = {
    amount, // в копейках
    payment_method: paymentMethod || undefined,
    merchant_customer_id: String(customerId),
    ip: String(ip || ''),
    description: String(description || '').slice(0, 128),
    metadata: metadata || {},
    return_url: returnUrl || undefined
  };

  return paradiseRequest('/payments', { method: 'POST', body });
}

// Получение статуса
async function paradiseGetPayment(uuid) {
  return paradiseRequest('/payments/' + encodeURIComponent(uuid), { method: 'GET' });
}

/* ---------- auth middleware ---------- */
/* ---------- auth middleware ---------- */
app.use((req, res, next) => {
  const token =
    req.cookies.token || (req.headers.authorization || "").split(" ")[1];
  if (!token) return next();
  const sessions = readJSON("sessions.json", {});
  const s = sessions[token];
  if (!s || s.expiresAt < now()) return next();
  const users = readJSON("users.json", {});
  const u = users[s.userId];
  if (!u || u.status === "banned") return next();
  req.user = u;
  req.session = s;
  next();
});
const requireAuth = (req, res, next) =>
  req.user ? next() : res.status(401).json({ error: "UNAUTH" });
const requireRole = (role) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "UNAUTH" });
  if (isSuperNick(req.user.nickname)) return next();
  const roles = req.user.roles || ["user"];
  if (!roles.includes(role)) return res.status(403).json({ error: "FORBIDDEN" });
  next();
};

/* ---------- health ---------- */
app.get("/api/health", (req, res) =>
  res.json({ ok: true, name: "Only Market", v: "3.4" })
);

/* ================= AUTH ================= */
app.post("/api/auth/register", async (req, res) => {
  const { email, password, nickname } = req.body || {};
  if (!email || !password || !nickname)
    return res.status(400).json({ error: "VALIDATION" });

  const users = readJSON("users.json", {});
  if (Object.values(users).some(u => u.email === email))
    return res.status(400).json({ error: "EMAIL_EXISTS" });
  if (Object.values(users).some(u => (u.nickname||"").toLowerCase() === String(nickname).toLowerCase()))
    return res.status(400).json({ error: "NICK_EXISTS" });

  const id = "u_" + nanoid(8);
  users[id] = {
    id, email, nickname,
    passwordHash: hashPw(password),
    roles: ["user"], status: "active", createdAt: now()
  };
  writeJSON("users.json", users);

  // сразу создаём сессию
  const sessions = readJSON("sessions.json", {});
  const token = "s_" + nanoid(16);
  sessions[token] = { id: token, userId: id, createdAt: now(), expiresAt: now()+30*24*3600*1000 };
  writeJSON("sessions.json", sessions);
  res.cookie("token", token, { httpOnly: false });
  res.json({ ok:true, user: users[id], token });
});


app.post("/api/auth/2fa-verify", async (req,res)=>{
  const { twofaId, code } = req.body||{};
  const two = readJSON("twofa.json", {});
  const it = two[String(twofaId)];
  if(!it || it.exp<now() || String(it.code)!==String(code)) return res.status(400).json({error:"BAD_2FA"});
  delete two[String(twofaId)]; writeJSON("twofa.json", two);
  const users = readJSON("users.json",{});
  const u = users[it.userId]; if(!u) return res.status(400).json({error:"NO_USER"});
  const sessions = readJSON("sessions.json", {});
  const token = "s_" + nanoid(16);
  sessions[token] = { id: token, userId: u.id, createdAt: now(), expiresAt: now()+30*24*3600*1000 };
  writeJSON("sessions.json", sessions);
  res.cookie("token", token, { httpOnly: false });
  res.json({ user: u, token });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "VALIDATION" });

  const users = readJSON("users.json", {});
  const u = Object.values(users).find(x => x.email === email);
  if (!u || !checkPw(password, u.passwordHash))
    return res.status(400).json({ error: "BAD_CREDENTIALS" });
  if (u.status === "banned") return res.status(403).json({ error: "BANNED" });

  const notify = readNotify();
  const tg = notify?.[u.id]?.telegram || {};
  const linked = !!(tg.linked && tg.chatId);

  if (!linked) {
    // выдаём код для привязки TG (тот же механизм, что в /api/telegram/request-code)
    const codes = readCodes();
    const linkCode = genCode();
    codes[u.id] = { userId: u.id, code: linkCode, exp: now() + 10*60*1000 };
    writeCodes(codes);
    return res.json({
      requireTgLink: true,
      linkCode,
      tgBot: "@" + (process.env.TELEGRAM_BOT_NAME || "onlymarket_marketplace_bot")
    });
  }

  // TG привязан — генерируем 2FA код и отправляем в TG
  const otps = readOTP();
  const challengeId = "ch_" + nanoid(10);
  const code = genCode();
  otps[challengeId] = {
    id: challengeId,
    userId: u.id,
    code,
    exp: now() + 10*60*1000,
    type: "login_tg"
  };
  writeOTP(otps);

  tgOutboxPushByUser(u.id, `Код входа: ${code}`);

  return res.json({ requiresTgCode: true, challengeId });


});

app.post("/api/auth/tg-verify", (req, res) => {
  const { challengeId, code } = req.body || {};
  const otps = readOTP();
  const it = otps[String(challengeId)];
  if (!it || it.exp < now() || String(it.code) !== String(code))
    return res.status(400).json({ error: "BAD_CODE" });

  delete otps[String(challengeId)];
  writeOTP(otps);

  const users = readJSON("users.json", {});
  const u = users[it.userId];
  if (!u) return res.status(404).json({ error: "NO_USER" });
  if (u.status === "banned") return res.status(403).json({ error: "BANNED" });

  const sessions = readJSON("sessions.json", {});
  const token = "s_" + nanoid(16);
  sessions[token] = { id: token, userId: u.id, createdAt: now(), expiresAt: now()+30*24*3600*1000 };
  writeJSON("sessions.json", sessions);
  res.cookie("token", token, { httpOnly: false });
  res.json({ ok: true, user: u, token });
});

app.post("/api/auth/email-verify", (req,res)=>{
  const { challengeId, code } = req.body || {};
  const otp = readEmailOTP();
  const it = otp[String(challengeId)];
  if(!it) return res.status(400).json({ error:"BAD_CHALLENGE" });
  if(it.exp < now()) { delete otp[String(challengeId)]; writeEmailOTP(otp); return res.status(400).json({ error:"EXPIRED" }); }
  if(String(it.code) !== String(code)) return res.status(400).json({ error:"BAD_CODE" });

  delete otp[String(challengeId)]; writeEmailOTP(otp);

  const users = readJSON("users.json", {});
  const u = users[it.userId]; if(!u) return res.status(404).json({ error:"NO_USER" });
  if(u.status === 'pending_email') u.status = 'active';

  // создаём сессию на 30 дней (JSON)
  const sessions = readJSON("sessions.json", {});
  const token = "s_" + nanoid(16);
  sessions[token] = { id: token, userId: u.id, createdAt: now(), expiresAt: now()+30*24*3600*1000 };
  writeJSON("sessions.json", sessions);

  writeJSON("users.json", users);
  res.cookie("token", token, { httpOnly: false });
  res.json({ ok:true, user: u, token });
});


app.post("/api/auth/logout", requireAuth, (req, res) => {
  const token =
    req.cookies.token || (req.headers.authorization || "").split(" ")[1];
  const sessions = readJSON("sessions.json", {});
  if (token) delete sessions[token];
  writeJSON("sessions.json", sessions);
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => res.json({ user: req.user || null }));


// Включение/выключение 2FA (через TG)
app.post("/api/security/2fa-toggle", requireAuth, (req,res)=>{
  const { enabled } = req.body||{};
  const users = readJSON("users.json", {});
  const u = users[req.user.id];
  if(!u) return res.status(404).json({error:"NOT_FOUND"});

  // нужна привязка TG
  const notify = readNotify();
  const tgLinked = !!notify?.[req.user.id]?.telegram?.linked;
  if(enabled && !tgLinked) return res.status(400).json({error:"NO_TG_LINK"});

  u.security = u.security||{};
  u.security.twofaTelegram = !!enabled;
  writeJSON("users.json", users);
  res.json({ok:true, twofaTelegram: u.security.twofaTelegram});
});

// --- admin helpers ---
function requireAdmin(req, res, next){
  if (!req.user || !isAdminUser(req.user)) {
    return res.status(403).json({ error: "FORBIDDEN" });
  }
  next();
}

app.post('/api/listings/:id/vip', requireAuth, (req,res)=>{
  const listings = readJSON('listings.json', {});
  const l = listings[req.params.id];
  if(!l) return res.status(404).json({error:'NOT_FOUND'});
  if(l.sellerId!==req.user.id && !isAdminUser(req.user))
    return res.status(403).json({error:'FORBIDDEN'});

  l.extra = l.extra || {};
  l.extra.vip = true;
  l.updatedAt = now();
  writeJSON('listings.json', listings);
  res.json({ ok:true });
});
app.get("/api/listings", (req, res) => {
  const all = readJSON("listings.json", {});
  let arr = Object.values(all).filter(l => l.status === "active");

  // VIP сверху → внутри VIP по vipAt desc → затем updatedAt/createdAt desc
  arr.sort((a,b)=>{
    const av = a.isVip ? 1 : 0;
    const bv = b.isVip ? 1 : 0;
    if (bv!==av) return bv-av;
    if (av===1 && bv===1) return (b.vipAt||0)-(a.vipAt||0);
    return (b.updatedAt||b.createdAt||0)-(a.updatedAt||a.createdAt||0);
  });

  // Новый режим: ?limit=50&cursor=ts
  const limit = Math.min(100, Math.max(1, Number(req.query.limit)||50));
  const cursor = Number(req.query.cursor||0);

  if (!cursor) {
    const slice = arr.slice(0, limit);
    const last = slice[slice.length-1];
    const nextCursor = last ? (last.updatedAt || last.createdAt || 0) : null;
    return res.json({ items: slice, nextCursor });
  } else {
    const start = arr.findIndex(x => (x.updatedAt||x.createdAt||0)===cursor);
    const from = start>=0 ? (start+1) : 0;
    const slice = arr.slice(from, from+limit);
    const last = slice[slice.length-1];
    const nextCursor = last ? (last.updatedAt || last.createdAt || 0) : null;
    return res.json({ items: slice, nextCursor });
  } 

});
app.get("/api/wallet/history", requireAuth, (req, res) => {
  const balances = readJSON("balances.json", {});
  const b = balances[req.user.id] || { available:0, hold:0, history:[] };
  const limit = Math.min(200, Math.max(1, Number(req.query.limit)||50));
  const offset = Math.max(0, Number(req.query.offset)||0);
  const arr = (b.history||[]).slice().sort((a,b)=>b.ts-a.ts);
  res.json({ items: arr.slice(offset, offset+limit), total: arr.length });
});

//});



/* ================= ADMIN CONFIG/FEES/NOTIFY SOUND ================= */

function sanitizeConfigForPublic(cfg) {
  const c = cfg || {};
  return {
    fees: { marketplace: c?.fees?.marketplace ?? 0.08 },
    notifySound: c?.notifySound || "",
    vipFee: c?.vipFee ?? 15
  };
}
// Список: поддержка/админы, с поиском ?q=
app.get('/api/support/tasks', requireAdmin, (req,res)=>{
  const q = String(req.query.q||'').toLowerCase();
  const tasksObj = readSupportTasks();
  let arr = Object.values(tasksObj);

  if(q){
    arr = arr.filter(t=>{
      const hay = [
        t.id,
        t.status,
        t.createdBy,
        t.assignedTo,
        t.payload?.kind,
        t.payload?.orderId,
        t.payload?.text,
        t.payload?.note
      ].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(q);
    });
  }

  arr.sort((a,b)=> (b.updatedAt||b.createdAt||0) - (a.updatedAt||a.createdAt||0));
  res.json(arr); // <= ВСЕГДА массив!
});

// Одна задача
app.get('/api/support/tasks/:id', requireAdmin, (req,res)=>{
  const t = readSupportTasks()[req.params.id];
  if(!t) return res.status(404).json({error:'NOT_FOUND'});
  res.json(t);
});

// Взять задачу
app.post('/api/support/tasks/:id/claim', requireAdmin, (req,res)=>{
  const all = readSupportTasks();
  const t = all[req.params.id];
  if(!t) return res.status(404).json({error:'NOT_FOUND'});
  if(t.status!=='open') return res.status(400).json({error:'BAD_STATUS'});
  t.status='claimed';
  t.assignedTo=req.user.id;
  t.updatedAt=now();
  writeSupportTasks(all);
  res.json(t);
});

// Закрыть задачу
app.post('/api/support/tasks/:id/resolve', requireAdmin, (req,res)=>{
  const { resolution='' } = req.body||{};
  const all = readSupportTasks();
  const t = all[req.params.id];
  if(!t) return res.status(404).json({error:'NOT_FOUND'});
  if(t.status==='resolved') return res.status(400).json({error:'ALREADY_RESOLVED'});
  t.status='resolved';
  t.resolution = String(resolution);
  t.updatedAt=now();
  writeSupportTasks(all);
  res.json(t);
});

// GET: админам — полный конфиг, остальным — «очищенный» (нужен для фронта — звук, vipFee)
app.get("/api/admin/config", (req, res) => {
  const cfg = readJSON("config.json", { fees: { marketplace: 0.08 }, vipFee: 15 });
  if (req.user && isAdminUser(req.user)) return res.json(cfg || {});
  return res.json(sanitizeConfigForPublic(cfg));
});

// POST: админ может править комиссию, звук уведомлений, реквизиты RuKassa, цену VIP
app.post("/api/admin/config", requireAuth, requireRole("admin"), (req, res) => {
  const { fees, notifySound, rukassa, vipFee } = req.body || {};
  const cfg = readJSON("config.json", { fees: { marketplace: 0.08 }, vipFee: 15 });

  if (typeof fees?.marketplace === "number")
    cfg.fees = { ...cfg.fees, marketplace: Math.max(0, Math.min(0.2, fees.marketplace)) };

  if (typeof notifySound === "string") cfg.notifySound = notifySound;

  if (rukassa && typeof rukassa === "object") {
    cfg.rukassa = cfg.rukassa || {};
    if (rukassa.shopId) cfg.rukassa.shopId = rukassa.shopId;
    if (rukassa.token) cfg.rukassa.token = rukassa.token;
    if (rukassa.baseUrl) cfg.rukassa.baseUrl = rukassa.baseUrl;
    if (rukassa.defaultCurrency) cfg.rukassa.defaultCurrency = rukassa.defaultCurrency;
  }

  if (typeof vipFee === "number" && vipFee >= 0) cfg.vipFee = vipFee;

  writeJSON("config.json", cfg);
  res.json({ ok: true, config: cfg });
});

// Публичный конфиг (например, для внешних виджетов)
app.get("/api/config-public", (req, res) => {
  const cfg = readJSON("config.json", { fees: { marketplace: 0.08 }, vipFee: 15 });
  res.json(sanitizeConfigForPublic(cfg));
});
import { OAuth2Client } from "google-auth-library";
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.post("/api/auth/google", async (req, res) => {
  try{
    const { credential } = req.body || {};
    if(!credential) return res.status(400).json({ error: "NO_TOKEN" });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if(!payload) return res.status(400).json({ error: "BAD_TOKEN" });

    const email = payload.email;
    const googleId = payload.sub;
    const name = payload.name || payload.given_name || "";

    let users = readJSON("users.json", {});
    let user = Object.values(users).find(u => u.googleId === googleId || u.email === email);

    if(!user){
      const id = nanoid();
      user = {
        id,
        email,
        nickname: name || email,
        googleId,
        provider: "google",
        status: "active",
        roles: ["buyer"],
        createdAt: Date.now(),
      };
      users[id] = user;
      writeJSON("users.json", users);
    }

    // создаём сессию так же, как в обычном login/register
    const sessions = readJSON("sessions.json", {});
    const token = nanoid();
    sessions[token] = { userId: user.id, createdAt: Date.now(), expiresAt: Date.now()+30*24*3600*1000 };
    writeJSON("sessions.json", sessions);

    res.cookie("token", token, { httpOnly: false });
    res.json({ user, token });
  }catch(e){
    console.error(e);
    res.status(500).json({ error: "GOOGLE_AUTH_FAILED" });
  }
});

/* ================= ADMIN (users/roles/bans) ================= */
app.post(
  "/api/admin/users/:id/ban",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const users = readJSON("users.json", {});
    const u = users[req.params.id];
    if (!u) return res.status(404).json({ error: "NOT_FOUND" });
    u.status = "banned";
    writeJSON("users.json", users);
    res.json({ ok: true });
  }
);
app.post(
  "/api/admin/users/:id/unban",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const users = readJSON("users.json", {});
    const u = users[req.params.id];
    if (!u) return res.status(404).json({ error: "NOT_FOUND" });
    u.status = "active";
    writeJSON("users.json", users);
    res.json({ ok: true });
  }
);
app.post(
  "/api/admin/users/:id/role",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const { add, remove } = req.body || {};
    const users = readJSON("users.json", {});
    const u = users[req.params.id];
    if (!u) return res.status(404).json({ error: "NOT_FOUND" });
    u.roles = Array.isArray(u.roles) ? u.roles : ["user"];
    if (add && !u.roles.includes(add)) u.roles.push(add);
    if (remove) u.roles = u.roles.filter((r) => r !== remove);
    writeJSON("users.json", users);
    res.json({ ok: true, roles: u.roles });
  }
);


/* ================= CATEGORIES ================= */
app.get("/api/categories", (req, res) => {
  let cats = readJSON("categories.json", []);
  if (!Array.isArray(cats)) cats = [];
  res.json(cats);
});
app.post(
  "/api/admin/category",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const { title, parentId = null, order = 0 } = req.body || {};
    if (!title || String(title).trim().length < 2)
      return res.status(400).json({ error: "BAD_TITLE" });
    let cats = readJSON("categories.json", []);
    if (!Array.isArray(cats)) cats = [];
    const cat = {
      id: "c_" + nanoid(8),
      title: String(title).trim(),
      parentId,
      order,
    };
    cats.push(cat);
    writeJSON("categories.json", cats);
    res.json(cat);
  }
);
app.put(
  "/api/admin/category/:id",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const { id } = req.params;
    const { title, parentId = null, order = 0 } = req.body || {};
    let cats = readJSON("categories.json", []);
    const i = cats.findIndex((c) => c.id === id);
    if (i === -1) return res.status(404).json({ error: "NOT_FOUND" });
    if (title && String(title).trim().length >= 2)
      cats[i].title = String(title).trim();
    cats[i].parentId = parentId ?? null;
    cats[i].order = Number(order) || 0;
    writeJSON("categories.json", cats);
    res.json(cats[i]);
  }
);
app.delete(
  "/api/admin/category/:id",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const id = req.params.id;
    let cats = readJSON("categories.json", []);
    if (!Array.isArray(cats)) cats = [];
    writeJSON("categories.json", cats.filter((c) => c.id !== id));
    res.json({ ok: true });
  }
);


/* ================= MEDIA (≤50KB generic + ≤30KB chat images) ================= */
function saveBase64ImageLimit(dataUrl, maxKB = 50) {
  if (!/^data:image\/(jpeg|jpg|png);base64,/.test(dataUrl || ""))
    return { error: "BAD_IMAGE_FORMAT" };
  const b64 = dataUrl.split(",")[1];
  if (!b64) return { error: "BAD_IMAGE_DATA" };
  const buf = Buffer.from(b64, "base64");
  if (buf.length > maxKB * 1024) return { error: "IMAGE_TOO_LARGE" };
  const id = "m_" + nanoid(12) + ".jpg";
  fs.writeFileSync(path.join(mediaDir, id), buf);
  return { id, size: buf.length };
}
const saveBase64Image = (d) => saveBase64ImageLimit(d, 50);

app.get("/media/:id", (req, res) => {
  const f = path.join(mediaDir, req.params.id);
  if (!fs.existsSync(f)) return res.status(404).end();
  res.setHeader("Content-Type", "image/jpeg");
  fs.createReadStream(f).pipe(res);
});


// === AVATAR UPLOAD (≤50KB) ===
app.post("/api/me/avatar", requireAuth, (req,res)=>{
  const { dataUrl } = req.body||{};
  if(!dataUrl) return res.status(400).json({error:"VALIDATION"});
  const r = saveBase64ImageLimit(dataUrl, 50);
  if(r.error) return res.status(400).json({error:r.error});
  const users = readJSON("users.json", {});
  const u = users[req.user.id];
  if(!u) return res.status(404).json({error:"NOT_FOUND"});
  u.avatar = "/media/"+r.id;
  writeJSON("users.json", users);
  return res.json({ ok:true, avatar: u.avatar });
});


/* ================= LISTINGS ================= */
// ПУБЛИЧНЫЙ список — только активные
app.get("/api/listings", (req, res) => {
  const all = readJSON("listings.json", {});
  const arr = Object.values(all).filter(l => l.status === "active");
  res.json(arr);
});

// Карточка по id: чужим — только active; своему продавцу/админу — всегда
app.get("/api/listings/:id", (req, res) => {
  const all = readJSON("listings.json", {});
  const l = all[req.params.id];
  if (!l) return res.status(404).json({ error: "NOT_FOUND" });
  const me = req.user || null;
  const isOwner = me && l.sellerId === me.id;
  const isAdm = me && isAdminUser(me);
  if (l.status !== "active" && !isOwner && !isAdm) {
    return res.status(403).json({ error: "FORBIDDEN" });
  }
  res.json(l);
});


app.post("/api/listings", requireAuth, (req, res) => {
  try {
    const {
      title,
      price,
      description = "",
      categoryId = null,
      image,                         // data:image/jpeg;base64,...
      type = "single",               // 'single' | 'multi' | 'stock'
      stock = null,
      delivery = "manual",           // 'manual' | 'auto'
      autoPayload = "",              // данные для автовыдачи (если delivery==='auto')
      extra = {}                     // любые доп. поля с фронта
    } = req.body || {};

    const p = Number(price);
    if (!categoryId || !title || !description || !image || !Number.isFinite(p) || p <= 0) {
      return res.status(400).json({
        error: "VALIDATION",
        message: "Категория, название, описание, цена и фото — обязательны"
      });
    }

    // сохраняем картинку (50KB лимит внутри saveBase64Image)
    const saved = saveBase64Image(image);
    if (saved?.error) return res.status(400).json({ error: saved.error });
    const mediaId = saved?.id || null;

    const listings = readJSON("listings.json", {});
    const id = "l_" + nanoid(10);

    const safeType     = ["single", "multi", "stock"].includes(type) ? type : "single";
    const safeStock    = safeType === "stock" ? Math.max(0, Number(stock) | 0) : null;
    const safeDelivery = ["manual", "auto"].includes(delivery) ? delivery : "manual";

    listings[id] = {
      id,
      sellerId: req.user.id,
      title: String(title).trim(),
      description: String(description).trim(),
      price: +p,
      categoryId,
      image: mediaId ? "/media/" + mediaId : null,

      type:  safeType,
      stock: safeStock,

      delivery:   safeDelivery,
      moderation: safeDelivery === "auto" ? "pending"    : "approved",
      status:     safeDelivery === "auto" ? "moderation" : "active",
      autoPayload: safeDelivery === "auto" ? String(autoPayload || "").slice(0, 4000) : "",

      extra: (extra && typeof extra === "object") ? extra : {},

      createdAt: now(),
      updatedAt: now()
    };

    writeJSON("listings.json", listings);
    res.json(listings[id]);
  } catch (e) {
    console.error("listings:create error", e);
    res.status(500).json({ error: "REQUEST_FAIL" });
  }
});

// Мои товары
app.get("/api/my/listings", requireAuth, (req,res)=>{
  const obj = readJSON("listings.json", {});
  const arr = Object.values(obj).filter(l => l.sellerId === req.user.id && l.status !== "deleted");
  arr.sort((a,b)=> b.updatedAt - a.updatedAt);
  res.json(arr);
});

// Редактирование
app.put("/api/listings/:id", requireAuth, (req,res)=>{
  const { id } = req.params;
  const { title, price, description, categoryId, status, type, stock } = req.body || {};
  const listings = readJSON("listings.json", {});
  const l = listings[id];
  if(!l) return res.status(404).json({ error:"NOT_FOUND" });
  const canEdit = (l.sellerId === req.user.id) || isAdminUser(req.user);
  if(!canEdit) return res.status(403).json({ error:"FORBIDDEN" });

  if(typeof title === "string" && title.trim().length>=1) l.title = title.trim();
  if(typeof price === "number" && price>=0) l.price = +price;
  if(typeof description === "string") l.description = description;
  if(typeof categoryId !== "undefined") l.categoryId = categoryId || null;
  if(typeof status === "string" && ["active","inactive","deleted"].includes(status)) l.status = status;
  if(typeof type === "string" && ["single","multi","stock"].includes(type)) l.type = type;
  if(l.type === "stock" && typeof stock !== "undefined") l.stock = Math.max(0, Number(stock||0)|0);
  l.updatedAt = now();
  writeJSON("listings.json", listings);
  res.json(l);
});

// Удаление (помечаем) 
app.delete("/api/listings/:id", requireAuth, (req,res)=>{
  const { id } = req.params;
  const listings = readJSON("listings.json", {});
  const l = listings[id];
  if(!l) return res.status(404).json({ error:"NOT_FOUND" });
  const canDel = (l.sellerId === req.user.id) || isAdminUser(req.user);
  if(!canDel) return res.status(403).json({ error:"FORBIDDEN" });
  l.status = "deleted";
  l.updatedAt = now();
  writeJSON("listings.json", listings);
  res.json({ ok:true });
});
// VIP апгрейд листинга (списываем vipFee, поднимаем isVip/vipAt)
app.post("/api/listings/:id/vip", requireAuth, (req,res)=>{
  const { id } = req.params;
  const listings = readJSON("listings.json", {});
  const l = listings[id];
  if(!l) return res.status(404).json({error:"NOT_FOUND"});
  const canVip = (l.sellerId===req.user.id) || isAdminUser(req.user);
  if(!canVip) return res.status(403).json({error:"FORBIDDEN"});

  const cfg = readJSON("config.json", { vipFee: 15 });
  const fee = Number(cfg.vipFee ?? 15);

  // списание с баланса продавца
  const balances = readJSON("balances.json", {});
  const b = balances[l.sellerId] || { available:0, hold:0, history:[] };
  if(b.available < fee) return res.status(400).json({error:"INSUFFICIENT_FUNDS", message:"Недостаточно средств для VIP"});

  b.available = +(b.available - fee).toFixed(2);
  b.history.push({ id:'h_'+nanoid(8), type:'vip_fee', amount:-fee, listingId: id, ts: now() });
  balances[l.sellerId] = b;
  writeJSON("balances.json", balances);

  l.isVip = true;
  l.vipAt = now();
  l.updatedAt = now();
  writeJSON("listings.json", listings);

  systemPostToRoom("user:"+l.sellerId, `Товар «${l.title}» поднят в VIP.`);
  res.json({ ok:true, listing:l });
});

// Очередь модерации для админов/саппорта
app.get("/api/admin/modqueue", requireAdmin, (req, res) => {
  const all = readJSON("listings.json", {});
  const arr = Object.values(all).filter(
    l => l.delivery === "auto" && (l.moderation === "pending" || l.status === "moderation")
  );
  res.json(arr);
});

// Одобрить/Отклонить конкретный товар
app.post("/api/admin/listings/:id/moderate", requireAdmin, (req, res) => {
  const { action, reason = "" } = req.body || {};
  const listings = readJSON("listings.json", {});
  const l = listings[req.params.id];
  if (!l) return res.status(404).json({ error: "NOT_FOUND" });
  if (l.delivery !== "auto") return res.status(400).json({ error: "NOT_AUTO" });

  if (action === "approve") {
    l.moderation = "approved";
    l.status = "active";
    l.updatedAt = now();
    writeJSON("listings.json", listings);
    try { tgSend(l.sellerId, `✅ Ваш товар «${l.title}» прошёл модерацию и опубликован.`); } catch {}
    return res.json({ ok: true });
  }
  if (action === "reject") {
    l.moderation = "rejected";
    l.status = "rejected";
    l.rejectReason = String(reason || "");
    l.updatedAt = now();
    writeJSON("listings.json", listings);
    try { tgSend(l.sellerId, `⛔ Товар «${l.title}» отклонён. Причина: ${l.rejectReason || '—'}`); } catch {}
    return res.json({ ok: true });
  }
  return res.status(400).json({ error: "BAD_ACTION" });
});

app.get("/api/support/tasks", requireAuth, requireRole("support"), (req,res)=>{
  const q = String(req.query.q||"").trim().toLowerCase();
  const list = readJSON("support_tasks.json", []); // если у тебя другое имя — оставь своё
  if(!q) return res.json(list);

  const users = readJSON("users.json", {});
  const filtered = (list||[]).filter(t=>{
    const idHit = (t.id||"").toLowerCase().includes(q);
    const kindHit = (t.payload?.kind||"").toLowerCase().includes(q);
    const textHit = (t.payload?.text||t.payload?.note||"").toLowerCase().includes(q);
    const orderHit = (t.payload?.orderId||"").toLowerCase().includes(q);
    const uid = t.userId || t.payload?.userId || t.payload?.ownerId;
    const nickHit = uid ? (users[uid]?.nickname||"").toLowerCase().includes(q) : false;
    return idHit || kindHit || textHit || orderHit || nickHit;
  });
  res.json(filtered);
});

/* ================= WALLET ================= */
app.get("/api/wallet", requireAuth, (req, res) => {
  const balances = readJSON("balances.json", {});
  const b = balances[req.user.id] || { available: 0, hold: 0, history: [] };
  res.json({ available: b.available || 0, hold: b.hold || 0 });
});
app.post("/api/wallet/deposit-request", requireAuth, (req, res) => {
  const { amount } = req.body || {};
  if (typeof amount !== "number" || amount <= 0)
    return res.status(400).json({ error: "VALIDATION" });
  const t = createSupportTask(req.user, { kind: "wallet:deposit", amount });
  systemPostToRoom(
    "support:" + req.user.id,
    `Поступила заявка на пополнение: ${amount} (task ${t.id})`
  );
  res.json({ ok: true, taskId: t.id });
});
app.post("/api/wallet/withdraw-request", requireAuth, (req, res) => {
  const { amount } = req.body || {};
  if (typeof amount !== "number" || amount <= 0)
    return res.status(400).json({ error: "VALIDATION" });
  const t = createSupportTask(req.user, { kind: "wallet:withdraw", amount });
  systemPostToRoom(
    "support:" + req.user.id,
    `Поступила заявка на вывод: ${amount} (task ${t.id})`
  );
  res.json({ ok: true, taskId: t.id });
});

// POST /api/pay/paradise/create
app.post('/api/pay/paradise/create', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { amountRub, paymentMethod } = req.body || {};

    const amt = Number(amountRub || 0);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ ok: false, error: 'VALIDATION', message: 'amountRub must be > 0' });
    }

    // нормализуем ip (берём первый из x-forwarded-for)
    const xff = String(req.headers['x-forwarded-for'] || '');
    const ipRaw = String(
      req.headers['x-real-ip'] ||
      (xff ? xff.split(',')[0].trim() : '') ||
      req.ip ||
      req.socket?.remoteAddress ||
      '0.0.0.0'
    );
    const ip = ipRaw.replace('::ffff:', '');

    const payment = await paradiseCreatePayment({
      amountRub: amt,
      customerId: user.id,
      ip,
      paymentMethod,
      description: `Пополнение кошелька пользователя ${user.id}`,
      metadata: { type: 'wallet_topup', userId: user.id },
      returnUrl: process.env.PARADISE_RETURN_URL || undefined
    });

    // ожидаемые поля: payment.uuid, payment.redirect_url, payment.status (waiting/success/expired/...)
    const uuid = payment?.uuid;
    if (!uuid) {
      return res.status(500).json({ ok: false, error: 'PARADISE_BAD_RESPONSE', message: 'No uuid in response' });
    }

    // сохраняем как "topup" в json (аналогично FK)
    const topups = readJSON('topups.json', {});
    topups[uuid] = {
      id: uuid,
      provider: 'PARADISE',
      userId: user.id,
      amount: amt,
      currency: 'RUB',
      status: payment?.status || 'waiting',
      redirect_url: payment?.redirect_url || null,
      credited: false,
      createdAt: now(),
    };
    writeJSON('topups.json', topups);

    res.json({
      ok: true,
      uuid,
      redirect_url: payment?.redirect_url,
      status: payment?.status || 'waiting'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'PARADISE_CREATE_ERROR', message: e.message });
  }
});

// GET /api/pay/paradise/status/:uuid
app.get('/api/pay/paradise/status/:uuid', requireAuth, async (req, res) => {
  try {
    const { uuid } = req.params;
    const user = req.user;

    const topups = readJSON('topups.json', {});
    const topup = topups[uuid];
    if (!topup) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
    if (String(topup.userId) !== String(user.id)) return res.status(403).json({ ok: false, error: 'FORBIDDEN' });

    const payment = await paradiseGetPayment(uuid);
    const status = payment?.status || 'waiting';

    // начисляем один раз, когда стало success
    if (status === 'success' && !topup.credited) {
      const balances = readJSON('balances.json', {});
      const b = balances[topup.userId] || { available: 0, hold: 0, history: [] };
      const add = +Number(topup.amount || 0);

      b.available = +(Number(b.available || 0) + add).toFixed(2);
      b.history.push({
        id: 'h_' + nanoid(8),
        type: 'deposit_paradise',
        amount: add,
        currency: 'RUB',
        provider: 'PARADISE',
        invoiceId: uuid,
        ts: Date.now(),
      });
      balances[topup.userId] = b;
      writeJSON('balances.json', balances);

      topup.status = 'success';
      topup.credited = true;
      topup.paidAt = Date.now();
      topups[uuid] = topup;
      writeJSON('topups.json', topups);
    } else if (status === 'expired' || status === 'error') {
      topup.status = status;
      topups[uuid] = topup;
      writeJSON('topups.json', topups);
    }

    res.json({ ok: true, status, amountRub: topup.amount });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'PARADISE_STATUS_ERROR', message: e.message });
  }
});

/* ================= ORDERS / ESCROW + DEAL ACTIONS ================= */
function countOrdersForListing(listingId, filterFn){
  const orders = readJSON("orders.json", {});
  return Object.values(orders).filter(o => o.listingId === listingId && (!filterFn || filterFn(o)));
}
function activeOrdersCount(listingId){
  return countOrdersForListing(listingId, o => !["completed","refunded","cancelled"].includes(o.status)).length;
}
function completedCount(listingId){
  return countOrdersForListing(listingId, o => o.status === "completed").length;
}

function processAutoReleases(){
  const orders = readJSON("orders.json", {});
  const balances = readJSON("balances.json", {});
  const cfg = readJSON("config.json", { fees:{ marketplace:0.08 } });

  let changed = false;
  for(const o of Object.values(orders)){
    if(o.status==='paid' && o.autoReleaseAt && now() >= o.autoReleaseAt){
      const fee = +((o.price||0)*(cfg.fees?.marketplace??0.08)).toFixed(2);
      const net = +(o.price - fee).toFixed(2);
      const bSeller = balances[o.sellerId] || {available:0,hold:0,history:[]};
      const bBuyer  = balances[o.buyerId]  || {available:0,hold:0,history:[]};

      if(bBuyer.hold >= o.price){
        bBuyer.hold -= o.price;
        bBuyer.history.push({id:'h_'+nanoid(8), type:'escrow_release', amount:0, orderId:o.id, ts:now()});
        bSeller.available += net;
        bSeller.history.push({id:'h_'+nanoid(8), type:'order_income', amount:net, orderId:o.id, ts:now()});
        balances[o.buyerId]=bBuyer; balances[o.sellerId]=bSeller;
        writeJSON("balances.json", balances);
        o.status='completed'; o.updatedAt=now(); o.completedAt=now();
        changed = true;
        systemPostToRoom(orderRoom(o.id), `Системное: заказ с авто-выдачей завершён автоматически.`);
      }
    }
  }
  if(changed) writeJSON("orders.json", orders);
}

const orderRoom = (id) => "order:" + id;

app.get("/api/orders", requireAuth, (req, res) => {
  const q = String(req.query.q||"").trim().toLowerCase();
  const orders = readJSON("orders.json", {});
  const listings = readJSON("listings.json", {});
  const users = readJSON("users.json", {});
  const me = req.user.id;

  let arr = Object.values(orders).filter(o => o.buyerId===me || o.sellerId===me);

  if(q){
    arr = arr.filter(o=>{
      const idHit = (o.id||"").toLowerCase().includes(q);
      const l = listings[o.listingId];
      const titleHit = !!l && (l.title||"").toLowerCase().includes(q);
      const buyerNick = (users[o.buyerId]?.nickname||"").toLowerCase();
      const sellerNick = (users[o.sellerId]?.nickname||"").toLowerCase();
      const userHit = buyerNick.includes(q) || sellerNick.includes(q);
      return idHit || titleHit || userHit;
    });
  }

  arr.sort((a,b)=> b.createdAt - a.createdAt);
  res.json(arr);
});

app.post("/api/orders", requireAuth, (req, res) => {
  const { listingId } = req.body || {};
  if (!listingId) return res.status(400).json({ error: "VALIDATION" });
  const listings = readJSON("listings.json", {});
  const l = listings[listingId];
  if (!l || l.status !== "active")
    return res.status(404).json({ error: "LISTING_NOT_FOUND" });
  if (l.sellerId === req.user.id)
    return res.status(400).json({ error: "OWN_LISTING" });

  // ⬇️ ВОТ СЮДА ВСТАВЬ СВОЙ БЛОК ПРО single/stock (до создания orders[id])
  // после получения l
  // блокируем покупку собственных — уже есть
  if(l.type === "single"){
    const act = activeOrdersCount(l.id);
    const comp = completedCount(l.id);
    if(l.status !== "active" || act>0 || comp>0)
      return res.status(400).json({ error: "UNAVAILABLE_SINGLE" });
  }
  if(l.type === "stock"){
    const comp = completedCount(l.id);
    const act = activeOrdersCount(l.id);
    const stock = Number(l.stock||0);
    if(stock <= 0 || (stock - comp - act) <= 0)
      return res.status(400).json({ error: "OUT_OF_STOCK" });
  }

  const orders = readJSON("orders.json", {});
  const id = "o_" + nanoid(10);
  orders[id] = {
    id,
    listingId,
    buyerId: req.user.id,
    sellerId: l.sellerId,
    price: l.price,
    status: "pending",
    createdAt: now(),
    updatedAt: now(),
    sellerDone: false,
    refundRequested: false,
    reviewLeft: false,
  };
  writeJSON("orders.json", orders);
  systemNotifyUser(l.sellerId, `Ваш товар купили. Заказ #${id}`);
  systemPostToRoom(orderRoom(id), `Системное: создан заказ #${id}`);
  res.json(orders[id]);
});

app.post("/api/orders/:id/pay", requireAuth, (req, res) => {
  const orders = readJSON("orders.json", {});
  const o = orders[req.params.id];
  if (!o) return res.status(404).json({ error: "NOT_FOUND" });
  if (o.buyerId !== req.user.id)
    return res.status(403).json({ error: "FORBIDDEN" });
  if (o.status !== "pending")
    return res.status(400).json({ error: "BAD_STATUS" });

  const balances = readJSON("balances.json", {});
  const b = balances[o.buyerId] || { available: 0, hold: 0, history: [] };
  if (b.available < o.price)
    return res.status(400).json({ error: "INSUFFICIENT_FUNDS" });
  b.available -= o.price;
  b.hold += o.price;
  b.history.push({
    id: "h_" + nanoid(8),
    type: "escrow_hold",
    amount: -o.price,
    orderId: o.id,
    ts: now(),
  });
  balances[o.buyerId] = b;
  writeJSON("balances.json", balances);

  o.status = "paid";
  o.updatedAt = now();
  writeJSON("orders.json", orders);
  systemPostToRoom(orderRoom(o.id), `Системное: оплата получена`);
  res.json(o);
  // если одноразовый — снимаем с витрины сразу после оплаты
// === Автовыдача после оплаты ===
try {
  const listings = readJSON("listings.json", {});
  const l = listings[o.listingId];

  if (l && l.delivery === "auto") {
    if (l.moderation === "approved") {
      const payload = String(l.autoPayload || "").trim();

      if (payload) {
        // отдать данные в чат сделки
        systemPostToRoom(orderRoom(o.id), `Автовыдача:\n${payload}`);
      } else {
        systemPostToRoom(orderRoom(o.id), `Автовыдача включена, но данные пустые.`);
      }

      // авто-релиз через 12 часов
      o.autoReleaseAt = now() + 12 * 3600 * 1000;
      writeJSON("orders.json", orders);
    } else {
      // модерация ещё не пройдена — предупредим участников
      systemPostToRoom(
        orderRoom(o.id),
        `Автовыдача на модерации. Данные будут выданы после одобрения.`
      );
    }
  }
} catch (e) {
  console.error("autodelivery block failed:", e);
}

});
app.post("/api/orders/:id/request-complete", requireAuth, (req, res) => {
  const orders = readJSON("orders.json", {});
  const o = orders[req.params.id];
  if (!o) return res.status(404).json({ error: "NOT_FOUND" });
  if (o.sellerId !== req.user.id)
    return res.status(403).json({ error: "FORBIDDEN" });
  if (!["paid", "delivered"].includes(o.status))
    return res.status(400).json({ error: "BAD_STATUS" });
  o.sellerDone = true;
  o.status = "delivered";
  o.updatedAt = now();
  writeJSON("orders.json", orders);
  systemPostToRoom(
    orderRoom(o.id),
    `Системное: продавец отметил сделку выполненной. Покупатель может подтвердить.`
  );
  res.json(o);
});
app.post("/api/orders/:id/refund-request", requireAuth, (req, res) => {
  const orders = readJSON("orders.json", {});
  const o = orders[req.params.id];
  if (!o) return res.status(404).json({ error: "NOT_FOUND" });
  if (o.sellerId !== req.user.id)
    return res.status(403).json({ error: "FORBIDDEN" });
  if (!["paid", "delivered"].includes(o.status))
    return res.status(400).json({ error: "BAD_STATUS" });
  o.refundRequested = true;
  o.updatedAt = now();
  writeJSON("orders.json", orders);
  createSupportTask(req.user, {
    kind: "refund",
    orderId: o.id,
    note: "Seller requested refund",
  });
  systemPostToRoom(
    orderRoom(o.id),
    `Системное: продавец запросил возврат. Поддержка уведомлена.`
  );
  res.json(o);
});

app.post("/api/orders/:id/confirm", requireAuth, (req, res) => {
  const orders = readJSON("orders.json", {});
  const o = orders[req.params.id];
  if (!o) return res.status(404).json({ error: "NOT_FOUND" });
  if (o.buyerId !== req.user.id)
    return res.status(403).json({ error: "FORBIDDEN" });
  if (o.status !== "delivered" || !o.sellerDone)
    return res.status(400).json({ error: "BAD_STATUS" });

  const balances = readJSON("balances.json", {});
  const cfg = readJSON("config.json", { fees: { marketplace: 0.08 } });
  const fee = +((o.price || 0) * (cfg.fees?.marketplace ?? 0.08)).toFixed(2);
  const net = +(o.price - fee).toFixed(2);

  const bBuyer =
    balances[o.buyerId] || { available: 0, hold: 0, history: [] };
  if (bBuyer.hold < o.price)
    return res.status(400).json({ error: "ESCROW_MISMATCH" });
  bBuyer.hold -= o.price;
  bBuyer.history.push({
    id: "h_" + nanoid(8),
    type: "escrow_release",
    amount: 0,
    orderId: o.id,
    ts: now(),
  });

  const bSeller =
    balances[o.sellerId] || { available: 0, hold: 0, history: [] };
  bSeller.available += net;
  bSeller.history.push({
    id: "h_" + nanoid(8),
    type: "order_income",
    amount: net,
    orderId: o.id,
    ts: now(),
  });

  balances[o.buyerId] = bBuyer;
  balances[o.sellerId] = bSeller;
  writeJSON("balances.json", balances);

  o.status = "completed";
  o.updatedAt = now();
  o.completedAt = now();
  writeJSON("orders.json", orders);
  systemPostToRoom(
    orderRoom(o.id),
    `Системное: заказ завершён. Средства зачислены продавцу.`
  );

  // обновляем listing после завершения
  const listings = readJSON("listings.json", {});
  const l = listings[o.listingId];
  if (l) {
    if (l.type === "single") {
      l.status = "inactive"; // одноразовый товар — больше не продаётся
    }
    if (l.type === "stock") {
      l.sold = (Number(l.sold||0)|0) + 1;
      const left = Math.max(0, (Number(l.stock||0)|0) - (Number(l.sold||0)|0));
      if (left <= 0) l.status = "inactive"; // кончился остаток
    }
    l.updatedAt = now();
    writeJSON("listings.json", listings);
  }

  res.json(o);
});

/* ================= REVIEWS ================= */
function readReviews(){ return readJSON('reviews.json', {}); }
function writeReviews(o){ writeJSON('reviews.json', o||{}); }

app.get('/api/reviews', (req, res)=>{
  const { sellerId, orderId } = req.query||{};
  const map = readReviews() || {};
  let arr = Object.values(map);
  if(sellerId) arr = arr.filter(r => r.sellerId === sellerId);
  if(orderId)  arr = arr.filter(r => r.orderId  === orderId);
  arr.sort((a,b)=> (b.ts||0)-(a.ts||0));
  res.json(arr);
});

app.post('/api/reviews', requireAuth, (req,res)=>{
  const { orderId, rating, text='' } = req.body||{};
  if(!orderId || !rating) return res.status(400).json({error:'VALIDATION'});

  const orders   = readJSON('orders.json', {});
  const listings = readJSON('listings.json', {});
  const o = orders[orderId];
  if(!o) return res.status(404).json({error:'ORDER_NOT_FOUND'});
  if(o.buyerId !== req.user.id) return res.status(403).json({error:'FORBIDDEN'});
  if(o.status!=='completed') return res.status(400).json({error:'ORDER_NOT_COMPLETED'});
  if(o.reviewLeft) return res.status(400).json({error:'ALREADY_REVIEWED'});

  const l = listings[o.listingId] || {};
  const id = 'r_'+nanoid(10);
  const r = {
    id,
    orderId,
    sellerId: o.sellerId,
    buyerId:  o.buyerId,
    rating:   Math.max(1, Math.min(5, Number(rating)||0)),
    text:     String(text||'').slice(0,1000),
    item: {

    listingId: o.listingId,
    title:     l.title || '',
    price:     priceSnap,
    image:     l.image || null

    },
    ts: now(),
    reply: null
  };
  const store = readReviews();
  store[id]=r; writeReviews(store);

  o.reviewLeft = true;
  o.updatedAt = now();
  orders[orderId]=o; writeJSON('orders.json', orders);

  res.json(r);
});

app.post('/api/reviews/:id/reply', requireAuth, (req,res)=>{
  const { id } = req.params;
  const { text='' } = req.body||{};
  const store = readReviews();
  const r = store[id];
  if(!r) return res.status(404).json({error:'NOT_FOUND'});
  if(r.sellerId !== req.user.id && !isAdminUser(req.user)) return res.status(403).json({error:'FORBIDDEN'});

  r.reply = { text: String(text||'').slice(0,1000), ts: now(), userId: req.user.id };
  store[id]=r; writeReviews(store);
  res.json({ ok:true, review: r });
});

/* ================= USERS PUBLIC LOOKUP ================= */
function getUserPublic(u) {
  const roles = u.roles || ["user"];
  const orders = readJSON("orders.json", {});
  const reviews = readJSON("reviews.json", {});
  const salesCompleted = Object.values(orders).filter(
    (o) => o.sellerId === u.id && o.status === "completed"
  ).length;
  const rList = Object.values(reviews).filter((r) => r.sellerId === u.id);
  const ratingCount = rList.length;
  const ratingAvg = ratingCount
    ? rList.reduce((s, x) => s + x.rating, 0) / ratingCount
    : 0;
  return {
    id: u.id,
    nickname: u.nickname,
    verified: roles.includes("verified"),
    avatar: u.avatar || "https://i.ibb.co/Y4HVSvPV/Group-1-2.png",
    stats: { salesCompleted, ratingCount, ratingAvg },

  };
}
app.get("/api/users/lookup", requireAuth, (req, res) => {
  const { ids = "" } = req.query;
  const idsArr = String(ids)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 200);
  const users = readJSON("users.json", {});
  const out = idsArr.map((id) =>
    users[id]
      ? getUserPublic(users[id])
      : {
          id,
          nickname: id,
          verified: false,
          stats: { salesCompleted: 0, ratingCount: 0, ratingAvg: 0 },
        }
  );
  res.json(out);
});
app.get("/api/users/:id/public", (req, res) => {
  const users = readJSON("users.json", {});
  const u = users[req.params.id];
  if (!u) return res.status(404).json({ error: "NOT_FOUND" });
  res.json(getUserPublic(u));
});




// Выдать/обновить код привязки Telegram
app.post("/api/telegram/request-code", requireAuth, (req, res) => {
  const codes = readCodes();
  const nowMs = now(); // миллисекунды!
  const userId = req.user.id;

  // попробовать найти существующий валидный код
  let foundCode = null;
  for(const [code, rec] of Object.entries(codes)){
    if(rec.userId === userId){
      const expiresAt = Number(rec.expiresAt || 0); // в мс
      if(expiresAt > nowMs){
        foundCode = { code, expiresAt };
        break;
      }else{
        // просрочен — удалить
        delete codes[code];
      }
    }
  }

  if(!foundCode){
    // сгенерить новый код
    const code = String(100000 + Math.floor(Math.random()*900000));
    const expiresAt = nowMs + TELEGRAM_CODE_TTL_SEC*1000; // в мс
    codes[code] = { userId, createdAt: nowMs, expiresAt };
    writeCodes(codes);
    foundCode = { code, expiresAt };
  }

  const secondsLeft = Math.max(0, Math.floor((foundCode.expiresAt - nowMs)/1000));
  res.json({ ok:true, code: foundCode.code, secondsLeft });
});
// Текущее состояние нотификаций/телеграма + оставшееся время кода (если есть)
app.get("/api/notify/settings", requireAuth, (req, res) => {
  const notify = readNotify();
  const me = notify[req.user.id] || {};
  const tele = me.telegram || { linked:false, enabled:false, chatId:null };

  // найдём активный код для этого пользователя
  const codes = readCodes();
  const nowMs = now();
  let code = null, secondsLeft = 0;
  for(const [c, rec] of Object.entries(codes)){
    if(rec.userId === req.user.id){
      const left = Math.floor((Number(rec.expiresAt||0) - nowMs)/1000);
      if(left > 0){
        code = c; secondsLeft = left;
      }
      break;
    }
  }

  res.json({ ok:true, telegram:{
    linked: !!tele.linked, enabled: !!tele.enabled, chatId: tele.chatId || null
  }, code, secondsLeft });
});

/* ================= SUPPORT TASKS ================= */
app.post("/api/support/report", requireAuth, (req, res) => {
  const { text = "", orderId = null } = req.body || {};
  const task = createSupportTask(req.user, {
    kind: "report",
    text: String(text).slice(0, 800),
    orderId,
  });
  systemPostToRoom(
    "support:" + req.user.id,
    `Новая заявка #${task.id}${orderId ? " по заказу " + orderId : ""}`
  );
  res.json(task);
});
app.get(
  "/api/support/tasks",
  requireAuth,
  requireRole("support"),
  (req, res) => {
    const tasks = readJSON("support_tasks.json", {});
    res.json(Object.values(tasks).sort((a, b) => b.createdAt - a.createdAt));
  }
);
app.post(
  "/api/support/tasks/:id/claim",
  requireAuth,
  requireRole("support"),
  (req, res) => {
    const tasks = readJSON("support_tasks.json", {});
    const t = tasks[req.params.id];
    if (!t) return res.status(404).json({ error: "NOT_FOUND" });
    if (t.status !== "open")
      return res.status(400).json({ error: "BAD_STATUS" });
    t.status = "claimed";
    t.assigneeId = req.user.id;
    t.updatedAt = now();
    writeJSON("support_tasks.json", tasks);
    res.json(t);
  }
);
app.post(
  "/api/support/tasks/:id/resolve",
  requireAuth,
  requireRole("support"),
  (req, res) => {
    const tasks = readJSON("support_tasks.json", {});
    const t = tasks[req.params.id];
    if (!t) return res.status(404).json({ error: "NOT_FOUND" });
    if (!["open", "claimed"].includes(t.status))
      return res.status(400).json({ error: "BAD_STATUS" });
    t.status = "resolved";
    t.updatedAt = now();
    t.resolution = req.body?.resolution || "";
    writeJSON("support_tasks.json", tasks);
    res.json(t);
  }
);

/* ================= CHAT (rooms + inbox + SSE + images) ================= */

function hideStore(){ return readJSON("chat_hidden.json", {}); }
function writeHideStore(o){ writeJSON("chat_hidden.json", o); }

app.post("/api/chat/hide", requireAuth, (req,res)=>{
  const { room } = req.body||{};
  if(!room || !room.startsWith('order:')) return res.status(400).json({error:"ONLY_ORDER_ROOM"});
  const orderId = room.slice(6);
  const orders = readJSON("orders.json", {});
  const o = orders[orderId];
  if(!o || o.status!=='completed') return res.status(400).json({error:"NOT_COMPLETED"});
  if(o.completedAt && now() - o.completedAt < 3*24*3600*1000)
    return res.status(400).json({error:"TOO_EARLY"});

  const hs = hideStore();
  hs[req.user.id] = hs[req.user.id] || {};
  hs[req.user.id][room]=true;
  writeHideStore(hs);
  res.json({ok:true});
});

const dmKey = (a, b) => {
  const [x, y] = [String(a), String(b)].sort();
  return "dm:" + x + ":" + y;
};
const subs = new Map(); // room -> Set(res)
const addSub = (room, res) => {
  if (!subs.has(room)) subs.set(room, new Set());
  subs.get(room).add(res);
};
const delSub = (room, res) => {
  const set = subs.get(room);
  if (!set) return;
  set.delete(res);
  if (!set.size) subs.delete(room);
};
const broadcast = (room, payload) => {
  const set = subs.get(room);
  if (!set) return;
  const data = "data: " + JSON.stringify(payload) + "\n\n";
  for (const r of set) {
    try {
      r.write(data);
    } catch {}
  }
};

function systemPostToRoom(room, text) {
  const store = readJSON("messages.json", { rooms: {} });
  if (!store.rooms[room]) store.rooms[room] = [];
  const msg = {
    id: "msg_" + nanoid(10),
    room,
    fromUserId: "system",
    text,
    ts: now(),
    system: true,
  };
  store.rooms[room].push(msg);
  if (store.rooms[room].length > 5000)
    store.rooms[room] = store.rooms[room].slice(-5000);
  writeJSON("messages.json", store);
  broadcast(room, { type: "message", item: msg });
}
function systemNotifyUser(userId, text) {
  const room = "user:" + userId;
  systemPostToRoom(room, text);
  try { tgSend(userId, text); } catch {}

}

// --- Telegram helper & settings ---
async function tgSend(userId, text){
  try{
    const cfg = readJSON("config.json", {});
    const token = cfg?.telegram?.botToken || process.env.TELEGRAM_BOT_TOKEN;
    if(!token) return;
    const users = readJSON("users.json", {});
    const u = users[userId];
    if(!u || !u.telegram || u.telegram.enabled === false || !u.telegram.chatId) return;
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ chat_id: u.telegram.chatId, text: String(text).slice(0, 350) })
    }).catch(()=>{});
  }catch{}
}

function tgOutboxPush(msg){
  const f = path.join(dataDir,'tg_outbox.json');
  let arr=[]; if(fs.existsSync(f)) try{ arr=JSON.parse(fs.readFileSync(f,'utf8')||'[]'); }catch{}
  arr.push({id:'tg_'+nanoid(8), ...msg, ts: now()});
  fs.writeFileSync(f, JSON.stringify(arr,null,2));
}
app.get("/api/notify/settings", requireAuth, (req,res)=>{
  const users = readJSON("users.json",{});
  const u = users[req.user.id]||{};
  const notif = readJSON("notify.json",{});
  const n = notif[req.user.id] || {telegram:{linked:false,enabled:false,chatId:null}};
  res.json({ telegram:n.telegram });
});
app.post("/api/telegram/request-code", requireAuth, (req,res)=>{
  const codes = readJSON("tg_codes.json",{});
  const code = String(Math.floor(100000+Math.random()*900000));
  codes[code] = { userId:req.user.id, ts:now() };
  writeJSON("tg_codes.json", codes);
  res.json({ code }); // показываем на сайте; юзер введёт в боте
});
app.post("/api/telegram/link", (req,res)=>{
  const { code, chatId, username="" } = req.body||{};
  const codes = readJSON("tg_codes.json",{});
  const itm = codes[String(code)];
  if(!itm) return res.status(400).json({error:"BAD_CODE"});
  const notif = readJSON("notify.json",{});
  notif[itm.userId] = notif[itm.userId] || {};
  notif[itm.userId].telegram = { linked:true, enabled:true, chatId:String(chatId), username };
  delete codes[String(code)];
  writeJSON("notify.json", notif); writeJSON("tg_codes.json", codes);
  res.json({ ok:true });
});
app.post("/api/notify/toggle", requireAuth, (req,res)=>{
  const { enable } = req.body||{};
  const notif = readJSON("notify.json",{});
  notif[req.user.id] = notif[req.user.id] || {telegram:{linked:false,enabled:false,chatId:null}};
  if(typeof enable==='boolean') notif[req.user.id].telegram.enabled = enable;
  writeJSON("notify.json", notif);
  res.json({ ok:true, telegram: notif[req.user.id].telegram });
});
try{
  if(text && !room.startsWith('global')){
    // отправим тем, кому относится (buyer/seller/support)
    if(room.startsWith('order:')){
      const id = room.slice(6);
      const orders = readJSON("orders.json",{});
      const o = orders[id];
      const notif = readJSON("notify.json",{});
      [o?.buyerId, o?.sellerId].filter(Boolean).forEach(uid=>{
        const t = notif[uid]?.telegram;
        if(t?.linked && t?.enabled && t.chatId) tgOutboxPush({ chatId:t.chatId, text: text });
      });
    }
    if(room.startsWith('support:')){
      const uid = room.split(':')[1];
      const notif = readJSON("notify.json",{});
      const t = notif[uid]?.telegram;
      if(t?.linked && t?.enabled && t.chatId) tgOutboxPush({ chatId:t.chatId, text: text });
    }
  }
}catch{}

app.get("/api/chat/inbox", requireAuth, (req, res) => {
  const store = readJSON("messages.json", { rooms: {} });
  const rooms = store.rooms || {};
  const entries = [];
  const isSupport = (req.user.roles || []).includes("support") || isSuperNick(req.user.nickname);
  const isAdmin = (req.user.roles || []).includes("admin") || isSuperNick(req.user.nickname);

  for (const [room, messages] of Object.entries(rooms)) {
    const last = messages[messages.length - 1];
    if (!last) continue;

    let include = false;
    if (room === "global") include = true;
    else if (room.startsWith("support:")) {
      const uid = room.split(":")[1];
      include = isSupport || uid === req.user.id;
    } else if (room.startsWith("user:")) include = room === "user:" + req.user.id;
    else if (room.startsWith("dm:")) include = room.includes(":" + req.user.id + ":");
    else if (room.startsWith("order:")) {
      if (isAdmin || isSupport) include = true; // allow admins/support to see any deal
      if (!include) {
        const orderId = room.slice(6);
        const orders = readJSON("orders.json", {});
        const o = orders[orderId];
        if (o && (o.buyerId === req.user.id || o.sellerId === req.user.id)) include = true;
      }
    }
    if (!include) continue;

    entries.push({
      room,
      lastText: last.text,
      ts: last.ts,
      lastFrom: last.fromUserId,
      unread: 0,
    });
  }
  entries.sort((a, b) => b.ts - a.ts);
  res.json(entries.slice(0, 200));
});

app.get("/api/chat/stream", requireAuth, (req, res) => {
  const { type = "global", peerId, orderId } = req.query;
  let room = "global";
  if (type === "dm") {
    if (!peerId) return res.status(400).end();
    room = dmKey(req.user.id, peerId);
  }
  if (type === "support") {
    const isSupport = (req.user.roles || []).includes("support") || isSuperNick(req.user.nickname);
    const uid = peerId && isSupport ? String(peerId) : req.user.id;
    room = "support:" + uid;
  }
  if (type === "order") {
    if (!orderId) return res.status(400).end();
    const isAdmin = (req.user.roles || []).includes("admin") || isSuperNick(req.user.nickname) || (req.user.roles || []).includes("support");
    if (!isAdmin) {
      const orders = readJSON("orders.json", {});
      const o = orders[String(orderId)];
      if (!o || (o.buyerId !== req.user.id && o.sellerId !== req.user.id))
        return res.status(403).end();
    }
    room = orderRoom(orderId);
  }
  if (type === "inbox") room = "user:" + req.user.id;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const store = readJSON("messages.json", { rooms: {} });
  const hist = (store.rooms[room] || []).slice(-50);
  res.write("data: " + JSON.stringify({ type: "history", items: hist }) + "\n\n");
  addSub(room, res);
  req.on("close", () => delSub(room, res));
});

app.post("/api/chat/send", requireAuth, (req, res) => {
  const { type = "global", peerId, orderId, text } = req.body || {};
  if (!text || !String(text).trim())
    return res.status(400).json({ error: "EMPTY" });

  let room = "global";
  if (type === "dm") {
    if (!peerId) return res.status(400).json({ error: "VALIDATION" });
    room = dmKey(req.user.id, peerId);
  }
  if (type === "support") {
    const isSupport = (req.user.roles || []).includes("support") || isSuperNick(req.user.nickname);
    const uid = peerId && isSupport ? String(peerId) : req.user.id;
    room = "support:" + uid;
  }
  if (type === "order") {
    if (!orderId) return res.status(400).json({ error: "VALIDATION" });
    // access check
    const isAdmin = isAdminUser(req.user);
    if (!isAdmin) {
      const orders = readJSON("orders.json", {});
      const o = orders[String(orderId)];
      if (!o || (o.buyerId !== req.user.id && o.sellerId !== req.user.id))
        return res.status(403).json({ error: "FORBIDDEN" });
    }
    room = orderRoom(orderId);
  }
  if (type === "inbox") room = "user:" + req.user.id;
  // -- Telegram pings to counterpart(s)
// TG: уведомим только вторую сторону (не себя), без системных/истории
try{
  notifyTelegramForChatMessage(room, msg, req.user);
}catch{}

// ...и где-нибудь выше в файле (рядом с chat utils) добавь функцию:
function shortText(x){ return String(x||'').replace(/\s+/g,' ').slice(0, 100); }

function notifyTelegramForChatMessage(room, msg, sender){
  if(msg.system) return;
  const text = msg.kind === 'image'
    ? 'Новое фото в чате'
    : 'Новое сообщение: ' + shortText(msg.text||'');

  if(room.startsWith('order:')){
    const orderId = room.slice(6);
    const orders = readJSON("orders.json", {});
    const o = orders[orderId];
    if(!o) return;

    // шлём только второй стороне
    const targets = [];
    if(sender?.id !== o.buyerId) targets.push(o.buyerId);
    if(sender?.id !== o.sellerId) targets.push(o.sellerId);

    targets.forEach(uid=>{
      tgOutboxPushByUser(uid, `Сделка #${orderId}: ${text}`);
    });
    return;
  }

  if(room.startsWith('dm:')){
    const [,a,b] = room.split(':');
    const me = sender?.id;
    const peer = (me===a?b:a);
    if(peer && peer!==me){
      tgOutboxPushByUser(peer, `Личные сообщения: ${text}`);
    }
    return;
  }

  if(room.startsWith('support:')){
    // support:<uid> — комната пользователя с поддержкой
    const uid = room.split(':')[1];
    // если пишет саппорт — уведомим пользователя; если пишет пользователь — саппорт обычно не в TG
    if(sender?.id !== uid){
      tgOutboxPushByUser(uid, `Поддержка: ${text}`);
    }
    return;
  }

  // global / user:* — не пушим
}

  try{
    if(type === "dm" && peerId && String(peerId) !== req.user.id){
      tgSend(String(peerId), `💬 Новое сообщение от ${req.user.nickname||req.user.id}: ${msg.text}`);
    }
    if(type === "order" && orderId){
      const orders = readJSON("orders.json", {});
      const o = orders[String(orderId)];
      if(o){
        const other = (o.buyerId === req.user.id) ? o.sellerId : o.buyerId;
        if(other && other !== req.user.id){
          tgSend(other, `📦 Заказ #${o.id}: новое сообщение от ${req.user.nickname||req.user.id}: ${msg.text}`);
        }
      }
    }
  // support: уведомляем вторую сторону (агента/юзера)
  if(type === "support"){
    const isSupport = isAdminUser(req.user);
    const targetId = isSupport ? String(peerId||"") : req.user.id; // если пишет агент — пингуем юзера
    if(!isSupport && targetId){ /* юзер пишет в поддержку — можно пинговать команду через отдельный чат */ }
    if(isSupport && targetId) tgSend(targetId, `🛟 Поддержка: новое сообщение: ${msg.text}`);
  }
}catch{}

  const store = readJSON("messages.json", { rooms: {} });
  if (!store.rooms[room]) store.rooms[room] = [];
  const msg = {
    id: "msg_" + nanoid(10),
    room,
    fromUserId: req.user.id,
    text: String(text).slice(0, 800),
    ts: now(),
  };
  store.rooms[room].push(msg);
  if (store.rooms[room].length > 5000)
    store.rooms[room] = store.rooms[room].slice(-5000);
  writeJSON("messages.json", store);
  broadcast(room, { type: "message", item: msg });

  // auto-create support task when a user writes to support room (first time)
  if (room.startsWith("support:") && !isAdminUser(req.user)) {
    const tasks = readJSON("support_tasks.json", {});
    const existing = Object.values(tasks).find(
      (t) => t.status !== "resolved" && t.createdBy === req.user.id && t.payload?.kind === "support:message"
    );
    if (!existing) {
      const t = createSupportTask(req.user, { kind: "support:message", text: msg.text });
      systemPostToRoom(room, `Создана задача поддержки #${t.id}`);
    }
  }

  res.json({ ok: true, item: msg });
});

// Upload chat image (order room only), ≤30KB, max 5 per deal
app.post("/api/chat/upload", requireAuth, (req, res) => {
  const { orderId, dataUrl } = req.body || {};
  if (!orderId || !dataUrl) return res.status(400).json({ error: "VALIDATION" });

  const orders = readJSON("orders.json", {});
  const o = orders[String(orderId)];
  const isAdmin = isAdminUser(req.user);
  if (!o && !isAdmin) return res.status(404).json({ error: "NOT_FOUND" });
  if (
    !isAdmin &&
    o &&
    o.buyerId !== req.user.id &&
    o.sellerId !== req.user.id
  )
    return res.status(403).json({ error: "FORBIDDEN" });

  // limit 5 images per deal
  const store = readJSON("messages.json", { rooms: {} });
  const room = orderRoom(orderId);
  const imgCount =
    (store.rooms[room] || []).filter((m) => m.kind === "image").length || 0;
  if (imgCount >= 5) return res.status(400).json({ error: "LIMIT_5_IMAGES" });

  const saved = saveBase64ImageLimit(dataUrl, 30);
  if (saved.error) return res.status(400).json({ error: saved.error });

  if (!store.rooms[room]) store.rooms[room] = [];
  const msg = {
    id: "msg_" + nanoid(10),
    room,
    fromUserId: req.user.id,
    text: "[image]",
    kind: "image",
    mediaId: saved.id,
    mediaUrl: "/media/" + saved.id,
    ts: now(),
  };
  store.rooms[room].push(msg);
  if (store.rooms[room].length > 5000)
    store.rooms[room] = store.rooms[room].slice(-5000);
  writeJSON("messages.json", store);
  broadcast(room, { type: "message", item: msg });

  res.json({ ok: true, item: msg });
});

/* ================= TELEGRAM LINKING & SETTINGS ================= */
// user -> request code (user copies code into bot)
app.post("/api/telegram/request-code", requireAuth, (req,res)=>{
  const codes = readJSON("telegram_codes.json", {});
  let code;
  do { code = String(Math.floor(100000 + Math.random()*900000)); } while(codes[code]);
  codes[code] = { userId: req.user.id, createdAt: now(), expiresAt: now() + 15*60*1000 };
  writeJSON("telegram_codes.json", codes);
  res.json({ code, expiresInSec: 15*60 });
});

// bot -> link by code (no auth; call from your bot)
app.post("/api/telegram/link", async (req,res)=>{
  const { code, chatId, username="" } = req.body || {};
  if(!code || !chatId) return res.status(400).json({ error: "VALIDATION" });
  const codes = readJSON("telegram_codes.json", {});
  const rec = codes[String(code)];
  if(!rec || rec.expiresAt < now()) return res.status(400).json({ error: "CODE_EXPIRED" });
  const users = readJSON("users.json", {});
  const u = users[rec.userId];
  if(!u) return res.status(404).json({ error: "USER_NOT_FOUND" });
  u.telegram = { chatId: String(chatId), username: String(username), enabled: true, linkedAt: now() };
  writeJSON("users.json", users);
  delete codes[String(code)];
  writeJSON("telegram_codes.json", codes);
  try{ await tgSend(u.id, "🔗 Телеграм успешно привязан!"); }catch{}
  res.json({ ok:true });
});

app.post("/api/telegram/unlink", requireAuth, (req,res)=>{
  const users = readJSON("users.json", {});
  const u = users[req.user.id];
  if(!u) return res.status(404).json({ error: "USER_NOT_FOUND" });
  if(u.telegram) u.telegram.enabled = false;
  writeJSON("users.json", users);
  res.json({ ok:true });
});

app.get("/api/notify/settings", requireAuth, (req,res)=>{
  const users = readJSON("users.json", {});
  const u = users[req.user.id] || {};
  res.json({ telegram: { linked: !!u.telegram?.chatId, enabled: u.telegram?.enabled !== false } });
});

app.post("/api/notify/settings", requireAuth, (req,res)=>{
  const { telegramEnabled } = req.body || {};
  const users = readJSON("users.json", {});
  const u = users[req.user.id];
  if(!u) return res.status(404).json({ error: "USER_NOT_FOUND" });
  if(!u.telegram?.chatId) return res.status(400).json({ error: "NOT_LINKED" });
  u.telegram.enabled = !!telegramEnabled;
  writeJSON("users.json", users);
  res.json({ ok:true });
});

/* ================= ADMIN OPS: balance adjust, deal pay/refund ================= */
app.post(
  "/api/admin/balance/adjust",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const { userId, amount, reason = "adjustment" } = req.body || {};
    if (!userId || typeof amount !== "number")
      return res.status(400).json({ error: "VALIDATION" });
    const balances = readJSON("balances.json", {});
    const b = balances[userId] || { available: 0, hold: 0, history: [] };
    b.available = +(b.available + amount).toFixed(2);
    b.history.push({
      id: "h_" + nanoid(8),
      type: "admin_adjust",
      amount,
      reason,
      ts: now(),
    });
    balances[userId] = b;
    writeJSON("balances.json", balances);
    res.json({ ok: true, balance: b });
  }
);

// Admin can force "pay" on behalf of buyer (creates hold even if buyer lacks funds)
app.post(
  "/api/admin/orders/:id/pay",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const { id } = req.params;
    const orders = readJSON("orders.json", {});
    const o = orders[id];
    if (!o) return res.status(404).json({ error: "NOT_FOUND" });
    if (o.status !== "pending")
      return res.status(400).json({ error: "BAD_STATUS" });

    const balances = readJSON("balances.json", {});
    const b = balances[o.buyerId] || { available: 0, hold: 0, history: [] };
    const need = o.price - (b.available || 0);
    if (need > 0) {
      // cover deficit by system injection
      b.history.push({
        id: "h_" + nanoid(8),
        type: "admin_force_hold_cover",
        amount: need,
        orderId: o.id,
        ts: now(),
      });
      b.available += need;
    }
    b.available -= o.price;
    b.hold += o.price;
    b.history.push({
      id: "h_" + nanoid(8),
      type: "escrow_hold",
      amount: -o.price,
      orderId: o.id,
      ts: now(),
    });
    balances[o.buyerId] = b;
    writeJSON("balances.json", balances);

    o.status = "paid";
    o.updatedAt = now();
    writeJSON("orders.json", orders);
    systemPostToRoom(orderRoom(o.id), `Системное: оплата отмечена админом`);
    res.json({ ok: true, order: o });
  }
);

// Admin refund: return hold to buyer (paid/delivered) or clawback from seller (completed)
app.post(
  "/api/admin/orders/:id/refund",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    const { id } = req.params;
    const orders = readJSON("orders.json", {});
    const o = orders[id];
    if (!o) return res.status(404).json({ error: "NOT_FOUND" });

    const balances = readJSON("balances.json", {});
    if (["paid", "delivered"].includes(o.status)) {
      const bBuyer =
        balances[o.buyerId] || { available: 0, hold: 0, history: [] };
      if (bBuyer.hold < o.price)
        return res.status(400).json({ error: "ESCROW_MISMATCH" });
      bBuyer.hold -= o.price;
      bBuyer.available += o.price;
      bBuyer.history.push({
        id: "h_" + nanoid(8),
        type: "escrow_refund",
        amount: o.price,
        orderId: o.id,
        ts: now(),
      });
      balances[o.buyerId] = bBuyer;
      writeJSON("balances.json", balances);
      o.status = "refunded";
      o.updatedAt = now();
      writeJSON("orders.json", orders);
      systemPostToRoom(orderRoom(o.id), `Системное: возврат оформлен админом`);
      return res.json({ ok: true, order: o });
    }

    if (o.status === "completed") {
      const bSeller =
        balances[o.sellerId] || { available: 0, hold: 0, history: [] };
      if (bSeller.available < o.price)
        return res
          .status(400)
          .json({ error: "SELLER_FUNDS_INSUFFICIENT" });
      bSeller.available -= o.price;
      bSeller.history.push({
        id: "h_" + nanoid(8),
        type: "admin_clawback",
        amount: -o.price,
        orderId: o.id,
        ts: now(),
      });
      const bBuyer =
        balances[o.buyerId] || { available: 0, hold: 0, history: [] };
      bBuyer.available += o.price;
      bBuyer.history.push({
        id: "h_" + nanoid(8),
        type: "refund_after_complete",
        amount: o.price,
        orderId: o.id,
        ts: now(),
      });
      balances[o.sellerId] = bSeller;
      balances[o.buyerId] = bBuyer;
      writeJSON("balances.json", balances);
      o.status = "refunded";
      o.updatedAt = now();
      writeJSON("orders.json", orders);
      systemPostToRoom(
        orderRoom(o.id),
        `Сис��емное: возврат после завершения оформлен админом`
      );
      return res.json({ ok: true, order: o });
    }

    return res.status(400).json({ error: "BAD_STATUS" });
  }
);

/* ================= PAYMENTS (FreeKassa, только опрос статуса, без notify) ================= */


const FK_DEFAULT_SCI = "https://pay.fk.money";
const FK_DEFAULT_API = "https://api.fk.life/v1";

// ---- helpers: env -> конфиг ----
function getFK() {
  const merchantId = parseInt(process.env.FK_MERCHANT_ID || "0", 10);
  return {
    merchantId,
    secret1: process.env.FK_SECRET1 || "",
    apiKey: process.env.FK_API_KEY || "",
    sciBase: process.env.FK_SCI_BASE || FK_DEFAULT_SCI,
    apiBase: process.env.FK_API_BASE || FK_DEFAULT_API
  };
}

const md5 = s => crypto.createHash("md5").update(String(s)).digest("hex");

// HMAC сигнатура для API v1 (orders/withdrawals)
function fkHmacSignature(data, apiKey) {
  const d = { ...data }; delete d.signature;
  const keys = Object.keys(d).sort();
  const line = keys.map(k => d[k]).join("|");
  return crypto.createHmac("sha256", apiKey).update(line).digest("hex");
}

// nonce должен всегда расти — сохраним в файлике
function fkNextNonce() {
  const f = path.join(dataDir, "fk_nonce.json");
  let v = 0;
  if (fs.existsSync(f)) {
    try { v = Number(JSON.parse(fs.readFileSync(f,"utf8")).value || 0); } catch {}
  }
  const nowTs = Date.now();
  const next = nowTs > v ? nowTs : (v + 1);
  fs.writeFileSync(f, JSON.stringify({ value: next }));
  return next;
}

/* -------- СОЗДАТЬ ССЫЛКУ (SCI) --------
   POST /api/pay/rukassa/create
   body: { amount, currency="RUB", email? }
   -> { invoiceId, payUrl }
----------------------------------------*/
app.post("/api/pay/rukassa/create", requireAuth, async (req, res) => {
  try {
    const { amount, currency = "RUB", email = "" } = req.body || {};
    const amt = Number(amount || 0);
    if (!amt || amt <= 0) return res.status(400).json({ error: "VALIDATION" });

    const fk = getFK();
    if (!fk.merchantId || !fk.secret1) {
      return res.status(400).json({ error: "NO_FK_CONFIG", message: "Set FK_MERCHANT_ID / FK_SECRET1 in .env" });
    }

    // наш внутренний id пополнения (однозначный в рамках системы)
    const invoiceId = "tp_" + nanoid(10);

    // подпись формы: md5(m:oa:secret1:currency:o)
    const sign = md5(`${fk.merchantId}:${amt.toFixed(2)}:${fk.secret1}:${currency}:${invoiceId}`);

    const params = new URLSearchParams({
      m: String(fk.merchantId),
      oa: amt.toFixed(2),
      o: invoiceId,
      s: sign,
      currency,
      lang: "ru",
      em: email,
      // любые свои поля с префиксом us_ прилетят обратно в notify (мы notify не используем,
      // но пусть будет для консистентности/отладки)
      us_user: req.user.id
    });
    const payUrl = `${fk.sciBase}/?${params.toString()}`;

    // сохраняем заявку (для фронта и будущего статуса)
    const topups = readJSON("topups.json", {});
    topups[invoiceId] = {
      id: invoiceId,
      userId: req.user.id,
      amount: amt,
      currency,
      fk: { location: payUrl },
      status: "created",
      credited: false,
      createdAt: now()
    };
    writeJSON("topups.json", topups);

    res.json({ invoiceId, payUrl });
  } catch (e) {
    console.error("FK(create) error", e);
    res.status(500).json({ error: "REQUEST_FAIL" });
  }
});

/* -------- ПРОВЕРИТЬ СТАТУС (API v1) --------
   GET /api/pay/rukassa/status?invoiceId=...
   -> { status: 'PAID'|'WAIT'|'CANCEL'|'ERROR'|'REFUND' }
   При 'PAID' зачисляем на баланс 1 раз.
----------------------------------------------*/
// .env: FK_SHOP_ID=777  FK_TOKEN=секрет
// ===== STATUS for front: /api/pay/rukassa/status?invoiceId=tp_xxx
app.get('/api/pay/rukassa/status', requireAuth, async (req, res) => {
  try {
    const invoiceId = String(req.query.invoiceId || '').trim(); // наш tp_xxx
    if (!invoiceId) return res.status(400).json({ error: 'VALIDATION' });

    const fk = getFK();
    const shopId = Number(process.env.FK_SHOP_ID || fk.merchantId || 0);
    const apiBase = fk.apiBase || 'https://api.fk.life/v1';
    if (!shopId || !fk.apiKey) {
      return res.json({ status: 'pending', error: 'FK_NOT_CONFIGURED' });
    }

    // 1) точечный запрос по paymentId
    const tryQuery = async (payload) => {
      const nonce = fkNextNonce();
      const body = { ...payload, shopId, nonce };
      body.signature = fkHmacSignature(body, fk.apiKey);
      const r = await fetch(apiBase + '/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => null);
      return { ok: r.ok, data: j };
    };

    let { ok, data } = await tryQuery({ paymentId: invoiceId });
    if (!ok || data?.type !== 'success') {
      // лог для отладки
      console.warn('FK /orders by paymentId resp:', ok, data);
    }

    // выковырять из ответа
    const pickPaid = (resp) => {
      const arr = Array.isArray(resp?.orders) ? resp.orders : [];
      const row = arr.find(x => String(x?.merchant_order_id || '') === invoiceId) || arr[0] || null;
      const paid = !!(row && Number(row.status) === 1);
      return { paid, row };
    };

    let { paid, row } = pickPaid(data);

    // 2) если не нашли — fallback: без paymentId, только оплаченные за последние 24ч
    if (!paid) {
      const since = new Date(Date.now() - 24*3600*1000).toISOString().slice(0,19).replace('T',' ');
      for (let page = 1; page <= 3 && !paid; page++) {
        const q = await tryQuery({ orderStatus: 1, dateFrom: since, page });
        if (q.data?.type !== 'success') break;
        const hit = pickPaid(q.data);
        if (hit.row && String(hit.row.merchant_order_id || '') === invoiceId) {
          paid = hit.paid; row = hit.row; break;
        }
        // если страниц меньше — выходим
        const totalPages = Number(q.data.pages || 1);
        if (page >= totalPages) break;
      }
    }

    // кредитуем один раз
    const topups = readJSON('topups.json', {});
    const tp = topups[invoiceId];
    if (!tp) return res.status(404).json({ error: 'NOT_FOUND' });

    if (paid && !tp.credited) {
      const balances = readJSON('balances.json', {});
      const b = balances[tp.userId] || { available: 0, hold: 0, history: [] };
      const add = +Number(tp.amount || 0);
      b.available = +(Number(b.available || 0) + add).toFixed(2);
      b.history.push({
        id: 'h_' + nanoid(8),
        type: 'deposit_fk',
        amount: add,
        currency: tp.currency || 'RUB',
        provider: 'FK',
        invoiceId,
        ts: Date.now(),
      });
      balances[tp.userId] = b;
      writeJSON('balances.json', balances);

      tp.status = 'paid';
      tp.credited = true;
      tp.paidAt = Date.now();
      topups[invoiceId] = tp;
      writeJSON('topups.json', topups);
    }

    return res.json({ status: paid ? 'paid' : 'pending' });
  } catch (e) {
    console.error('rukassa/status fail', e);
    res.status(500).json({ error: 'REQUEST_FAIL' });
  }
});

// =====================================================
// /api/pay/:provider контракт (используется в модалке "Пополнить")
// front ждёт: POST -> { invoiceId, payUrl }, GET -> { status: 'paid'|'pending' }
// =====================================================

// ---------- CryptoBot ----------
app.post('/api/pay/cryptobot/create', requireAuth, async (req, res) => {
  try {
    if (!CRYPTO_TOKEN) return res.status(400).json({ error: 'CRYPTOBOT_NOT_CONFIGURED' });

    const { amount, fiat = 'RUB', accepted_assets = 'USDT,TON,BTC,ETH' } = req.body || {};
    const amt = Number(amount || 0);
    if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'VALIDATION' });

    const payload = {
      currency_type: 'fiat',
      fiat,
      amount: String(amt),
      accepted_assets,
      description: 'Пополнение баланса',
      allow_comments: false,
      allow_anonymous: true,
      expires_in: 600
    };

    const r = await fetch('https://pay.crypt.bot/api/createInvoice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Crypto-Pay-API-Token': CRYPTO_TOKEN },
      body: JSON.stringify(payload)
    });
    const j = await r.json().catch(() => null);
    if (!j?.ok) throw new Error(j?.error || 'cryptobot error');

    const inv = j.result; // { invoice_id, status, bot_invoice_url, ... }
    const invoiceId = 'cb_' + inv.invoice_id;
    const payUrl = inv.bot_invoice_url;

    const topups = readJSON('topups.json', {});
    topups[invoiceId] = {
      id: invoiceId,
      provider: 'CRYPTOBOT',
      userId: req.user.id,
      amount: amt,
      currency: fiat,
      status: inv.status || 'active',
      credited: false,
      createdAt: now(),
    };
    writeJSON('topups.json', topups);

    res.json({ invoiceId, payUrl });
  } catch (e) {
    console.error('cryptobot/create fail', e);
    res.status(500).json({ error: 'REQUEST_FAIL' });
  }
});

app.get('/api/pay/cryptobot/status', requireAuth, async (req, res) => {
  try {
    if (!CRYPTO_TOKEN) return res.json({ status: 'pending', error: 'CRYPTOBOT_NOT_CONFIGURED' });

    const invoiceId = String(req.query.invoiceId || '').trim(); // cb_123
    if (!invoiceId) return res.status(400).json({ error: 'VALIDATION' });

    const topups = readJSON('topups.json', {});
    const tp = topups[invoiceId];
    if (!tp) return res.status(404).json({ error: 'NOT_FOUND' });
    if (String(tp.userId) !== String(req.user.id)) return res.status(403).json({ error: 'FORBIDDEN' });

    const invNum = invoiceId.replace(/^cb_/, '');
    const r = await fetch('https://pay.crypt.bot/api/getInvoices?invoice_ids=' + encodeURIComponent(invNum), {
      headers: { 'Crypto-Pay-API-Token': CRYPTO_TOKEN }
    });
    const j = await r.json().catch(() => null);
    if (!j?.ok) throw new Error(j?.error || 'getInvoices failed');

    const inv = (j.result || [])[0];
    if (!inv) return res.json({ status: 'pending' });

    const paid = inv.status === 'paid';
    if (paid && !tp.credited) {
      const balances = readJSON('balances.json', {});
      const b = balances[tp.userId] || { available: 0, hold: 0, history: [] };
      const add = +Number(tp.amount || 0);

      b.available = +(Number(b.available || 0) + add).toFixed(2);
      b.history.push({
        id: 'h_' + nanoid(8),
        type: 'deposit_cryptobot',
        amount: add,
        currency: tp.currency || 'RUB',
        provider: 'CryptoBot',
        invoiceId,
        ts: Date.now(),
      });
      balances[tp.userId] = b;
      writeJSON('balances.json', balances);

      tp.status = 'paid';
      tp.credited = true;
      tp.paidAt = Date.now();
      topups[invoiceId] = tp;
      writeJSON('topups.json', topups);
    }

    res.json({ status: paid ? 'paid' : 'pending', rawStatus: inv.status });
  } catch (e) {
    console.error('cryptobot/status fail', e);
    res.status(500).json({ error: 'REQUEST_FAIL' });
  }
});

// ---------- Stripe ----------
// ВАЖНО: полноценный статус требует webhooks (Stripe), поэтому тут "pending".
// Если нужно — добавим webhook endpoint и подтверждение.
app.post('/api/pay/stripe/create', requireAuth, async (req, res) => {
  try {
    const { amount } = req.body || {};
    const amt = Number(amount || 0);
    if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'VALIDATION' });

    const connectedAccountId = process.env.STRIPE_CONNECTED_ACC || null;
    const price = await stripe.prices.create({
      unit_amount: Math.round(amt * 100),
      currency: 'rub',
      product_data: { name: 'Only Market пополнение' },
    });

    const link = await stripe.paymentLinks.create({
      line_items: [{ price: price.id, quantity: 1 }],
      ...(connectedAccountId ? { transfer_data: { destination: connectedAccountId } } : {}),
      // комиссия маркетплейса — как и в /api/payments/create
      application_fee_amount: Math.round(amt * 0.7),
    });

    const invoiceId = 'st_' + nanoid(10);
    const topups = readJSON('topups.json', {});
    topups[invoiceId] = {
      id: invoiceId,
      provider: 'STRIPE',
      userId: req.user.id,
      amount: amt,
      currency: 'RUB',
      status: 'created',
      credited: false,
      stripe: { paymentLinkId: link.id, url: link.url },
      createdAt: now(),
    };
    writeJSON('topups.json', topups);

    res.json({ invoiceId, payUrl: link.url });
  } catch (e) {
    console.error('stripe/create fail', e);
    res.status(500).json({ error: 'REQUEST_FAIL' });
  }
});

app.get('/api/pay/stripe/status', requireAuth, async (req, res) => {
  try {
    const invoiceId = String(req.query.invoiceId || '').trim();
    if (!invoiceId) return res.status(400).json({ error: 'VALIDATION' });

    const topups = readJSON('topups.json', {});
    const tp = topups[invoiceId];
    if (!tp) return res.status(404).json({ error: 'NOT_FOUND' });
    if (String(tp.userId) !== String(req.user.id)) return res.status(403).json({ error: 'FORBIDDEN' });

    // без webhook — только pending
    res.json({ status: tp.credited ? 'paid' : 'pending', note: 'Stripe status needs webhooks' });
  } catch (e) {
    console.error('stripe/status fail', e);
    res.status(500).json({ error: 'REQUEST_FAIL' });
  }
});




app.post("/api/admin/listings/:id/moderate", requireAuth, requireRole("admin"), (req,res)=>{
  const { status } = req.body||{}; // 'approved' | 'rejected'
  const listings = readJSON("listings.json", {});
  const l = listings[req.params.id];
  if(!l) return res.status(404).json({error:"NOT_FOUND"});
  if(l.delivery!=='auto') return res.status(400).json({error:"NOT_AUTO"});
  if(!['approved','rejected'].includes(status)) return res.status(400).json({error:"BAD_STATUS"});
  l.moderation = status;
  l.status = status==='approved' ? 'active' : 'inactive';
  l.updatedAt = now();
  writeJSON("listings.json", listings);
  res.json(l);
});

app.get("/api/auth/2fa/status", async (req,res)=>{
  const { challengeId } = req.query||{};
  if(!challengeId) return res.status(400).json({error:"NO_ID"});
  const challenges = read2FA();
  const ch = challenges[challengeId];
  if(!ch) return res.status(404).json({error:"NOT_FOUND"});

  if(ch.expiresAt < now()){
    delete challenges[challengeId];
    write2FA(challenges);
    return res.status(400).json({error:"EXPIRED"});
  }

  if(ch.status === "approved"){
    // создать обычную сессию И вычистить челлендж
    const users = readJSON("users.json", {});
    const u = users[ch.userId];
    if(!u || u.status==='banned') return res.status(403).json({error:"FORBIDDEN"});

    const sessions = readJSON("sessions.json", {});
    const token = "s_" + nanoid(16);
    sessions[token] = {
      id: token, userId: u.id, createdAt: now(), expiresAt: now() + 30*24*3600*1000
    };
    writeJSON("sessions.json", sessions);
    res.cookie("token", token, { httpOnly: false });

    delete challenges[challengeId];
    write2FA(challenges);

    return res.json({ ok:true, user: u, token });
  }

  if(ch.status === "denied") return res.status(400).json({error:"DENIED"});

  return res.json({ pending:true });
});

app.post("/api/admin/listings/:id/moderate", requireAuth, requireRole("admin"), (req,res)=>{
  const { id } = req.params;
  const { status } = req.body||{}; // 'approved' | 'rejected'
  const listings = readJSON("listings.json", {});
  const l = listings[id];
  if(!l) return res.status(404).json({error:"NOT_FOUND"});
  if(l.delivery!=='auto') return res.status(400).json({error:"NOT_AUTO"});
  if(!['approved','rejected'].includes(status)) return res.status(400).json({error:"BAD_STATUS"});
  l.moderation = status;
  if(status==='approved' && l.status==='moderation') l.status='active';
  if(status==='rejected') l.status='disabled';
  l.updatedAt = now();
  writeJSON("listings.json", listings);
  res.json({ok:true, listing:l});
});
function sweepAutoReleases(){
  try{
    const orders = readJSON("orders.json", {});
    const cfg = readJSON("config.json", { fees:{ marketplace:0.08 } });
    let changed = false;
    for(const o of Object.values(orders)){
      if(!o.autoReleaseAt) continue;
      if(o.status!=='paid' && o.status!=='delivered') continue;
      if(now() < o.autoReleaseAt) continue;

      // релиз средств как в confirm
      const balances = readJSON("balances.json", {});
      const fee = +((o.price || 0) * (cfg.fees?.marketplace ?? 0.08)).toFixed(2);
      const net = +(o.price - fee).toFixed(2);

      const bBuyer = balances[o.buyerId] || { available:0, hold:0, history:[] };
      if(bBuyer.hold < o.price) continue; // неконсистентно — пропустим

      bBuyer.hold -= o.price;
      bBuyer.history.push({ id:"h_"+nanoid(8), type:"escrow_release", amount:0, orderId:o.id, ts:now() });

      const bSeller = balances[o.sellerId] || { available:0, hold:0, history:[] };
      bSeller.available += net;
      bSeller.history.push({ id:"h_"+nanoid(8), type:"order_income_auto", amount: net, orderId:o.id, ts:now() });
      balances[o.buyerId]=bBuyer; balances[o.sellerId]=bSeller;
      writeJSON("balances.json", balances);

      o.status='completed';
      o.completedAt = now();
      delete o.autoReleaseAt;
      orders[o.id]=o;
      changed = true;
      systemPostToRoom(orderRoom(o.id), `Системное: авто-выплата через 12 часов выполнена. Средства зачислены продавцу.`);
    }
    if(changed) writeJSON("orders.json", orders);
  }catch(e){ console.error("sweepAutoReleases error", e); }
}
setInterval(sweepAutoReleases, 5*60*1000);



// =============== STRIPE ===============

app.post('/api/payments/create', async (req, res) => {
  try {
    const { amount, gateway } = req.body;

    if (gateway === 'stripe') {
      const connectedAccountId = process.env.STRIPE_CONNECTED_ACC || 'acct_xxx';
      const price = await stripe.prices.create({
        unit_amount: Math.round(amount * 100),
        currency: 'rub',
        product_data: { name: 'Only Market пополнение' },
      });

      const link = await stripe.paymentLinks.create({
        line_items: [{ price: price.id, quantity: 1 }],
        transfer_data: { destination: connectedAccountId },
        application_fee_amount: Math.round(amount * 0.7),
      });

      return res.json({
        id: 'pl_' + link.id,
        redirectUrl: link.url,
        gateway: 'stripe'
      });
    }

    // если не Stripe — вернуть ошибку
    res.status(400).json({ error: 'UNSUPPORTED_GATEWAY' });

  } catch (e) {
    console.error('Stripe create failed', e);
    res.status(500).json({ error: 'REQUEST_FAIL' });
  }
});

//========CryptoBot=======

// npm i node-fetch uuid

const CRYPTO_TOKEN = process.env.CRYPTOPAY_TOKEN; // из @CryptoBot → Crypto Pay → My Apps

app.post('/api/payments/cryptobot/invoice', async (req,res)=>{
  try{
    const { amount, fiat='RUB', accepted_assets='USDT,TON,BTC,ETH' } = req.body;
    if(!(amount>0)) return res.status(400).json({error:'bad params'});

    const payload = {
      currency_type: 'fiat',
      fiat,
      amount: String(amount),
      accepted_assets,
      description: 'Пополнение баланса',
      allow_comments: false,
      allow_anonymous: true,
      expires_in: 600 // 10 минут
    };

    const r = await fetch('https://pay.crypt.bot/api/createInvoice', {
      method:'POST',
      headers:{ 'Content-Type':'application/json', 'Crypto-Pay-API-Token': CRYPTO_TOKEN },
      body: JSON.stringify(payload)
    });
    const j = await r.json();
    if(!j.ok) throw new Error(j.error||'cryptobot error');

    const inv = j.result; // { invoice_id, status, bot_invoice_url, ... }
    const paymentId = 'cb_'+inv.invoice_id; // сохрани в БД
    res.json({ id: paymentId, redirectUrl: inv.bot_invoice_url, gateway:'cryptobot' });
  }catch(e){
    console.error(e); res.status(500).json({error:'cryptobot failed'});
  }
});

// Статус по CryptoBot
app.get('/api/payments/cryptobot/status', async (req,res)=>{
  try{
    const invoiceId = req.query.invoice_id;
    const r = await fetch('https://pay.crypt.bot/api/getInvoices?invoice_ids='+invoiceId, {
      headers:{ 'Crypto-Pay-API-Token': CRYPTO_TOKEN }
    });
    const j = await r.json();
    if(!j.ok) throw new Error(j.error||'getInvoices failed');
    const inv = (j.result||[])[0];
    if(!inv) return res.json({status:'not_found'});
    res.json({ status: inv.status==='paid' ? 'succeeded' : (inv.status==='active'?'processing':'expired'),
               method:'CryptoBot', external_id: inv.invoice_id });
  }catch(e){
    console.error(e); res.status(500).json({error:'status failed'});
  }
});


/* ---------- start ---------- */
const PORT = process.env.PORT || 3050;
app.listen(PORT, () =>
  console.log("Only Market server v3.4 on http://localhost:" + PORT)
);


