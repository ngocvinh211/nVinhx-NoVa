require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "16kb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = Number(process.env.PORT || 8787);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const DATA_FILE = path.resolve(__dirname, process.env.DATA_FILE || "./data/keys.json");

if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 24 || ADMIN_TOKEN === "REPLACE_WITH_A_LONG_RANDOM_SECRET") {
  console.error("Set a strong ADMIN_TOKEN (at least 24 characters) in server/.env");
  process.exit(1);
}

function loadKeys() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); }
  catch { return []; }
}
function saveKeys(keys) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2), { mode: 0o600 });
}
function adminOnly(req, res, next) {
  const provided = req.get("x-admin-token") || "";
  const a = Buffer.from(provided);
  const b = Buffer.from(ADMIN_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}
function makeKey() {
  return "NOVA-" + crypto.randomBytes(4).toString("hex").toUpperCase() + "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase();
}
app.get("/api/health", (_req, res) => res.json({ ok: true, service: "nVinhx NoVa Key Server" }));

app.post("/api/admin/keys", adminOnly, (req, res) => {
  const label = String(req.body?.label || "user").trim().slice(0, 80);
  const durationDays = Number(req.body?.durationDays);
  if (!Number.isInteger(durationDays) || durationDays < 1 || durationDays > 36500) {
    return res.status(400).json({ ok: false, error: "durationDays must be an integer from 1 to 36500" });
  }
  const keys = loadKeys();
  let key = makeKey();
  while (keys.some(k => k.key === key)) key = makeKey();
  const now = Date.now();
  const record = {
    id: crypto.randomUUID(),
    key,
    label,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + durationDays * 86400000).toISOString(),
    revoked: false,
    deviceId: null
  };
  keys.push(record);
  saveKeys(keys);
  res.status(201).json({ ok: true, key: record });
});

app.get("/api/admin/keys", adminOnly, (_req, res) => {
  const keys = loadKeys().map(({ key, ...rest }) => ({ ...rest, key }));
  res.json({ ok: true, keys });
});

app.post("/api/admin/keys/:id/revoke", adminOnly, (req, res) => {
  const keys = loadKeys();
  const record = keys.find(k => k.id === req.params.id);
  if (!record) return res.status(404).json({ ok: false, error: "Key not found" });
  record.revoked = true;
  record.revokedAt = new Date().toISOString();
  saveKeys(keys);
  res.json({ ok: true });
});

app.post("/api/validate", (req, res) => {
  const key = String(req.body?.key || "").trim().toUpperCase();
  const deviceId = String(req.body?.deviceId || "").trim().slice(0, 128) || null;
  if (!key) return res.status(400).json({ ok: false, valid: false, error: "Key is required" });
  const keys = loadKeys();
  const record = keys.find(k => k.key === key);
  if (!record) return res.status(200).json({ ok: true, valid: false, reason: "not_found" });
  if (record.revoked) return res.status(200).json({ ok: true, valid: false, reason: "revoked" });
  if (Date.now() >= Date.parse(record.expiresAt)) return res.status(200).json({ ok: true, valid: false, reason: "expired" });
  if (deviceId && record.deviceId && record.deviceId !== deviceId) {
    return res.status(200).json({ ok: true, valid: false, reason: "device_mismatch" });
  }
  if (deviceId && !record.deviceId) {
    record.deviceId = deviceId;
    saveKeys(keys);
  }
  res.json({ ok: true, valid: true, expiresAt: record.expiresAt, label: record.label });
});

app.listen(PORT, () => console.log(`nVinhx NoVa Key Server listening on port ${PORT}`));
