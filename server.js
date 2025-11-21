const express = require("express");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

const app = express();

app.use(express.json());
app.use(express.static(__dirname));

// ===== Env Vars =====
const ADMIN_KEY = process.env.ADMIN_KEY || "CHANGE_ME_ADMIN";
const API_KEY = process.env.API_KEY || "P9-LOADER-2025";

// ===== Files =====
const USERS_FILE = path.join(__dirname, "users.json");

// ===== Helpers =====
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  try {
    const raw = fs.readFileSync(USERS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function saveUsers(obj) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(obj, null, 2), "utf8");
}

// تأكد أن الملف موجود
if (!fs.existsSync(USERS_FILE)) {
  saveUsers({});
}

// ===== Middlewares =====
function requireAdmin(req, res, next) {
  const key = req.header("x-admin-key");
  if (!key || key !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, code: "INVALID_ADMIN_KEY" });
  }
  next();
}

function requireLoader(req, res, next) {
  const key = req.header("x-api-key");
  if (!key || key !== API_KEY) {
    return res.status(403).json({ ok: false, code: "INVALID_API_KEY" });
  }
  next();
}

// ===================== LOADER API =====================
// POST /api/loader/login
app.post("/api/loader/login", requireLoader, (req, res) => {
  const { username, password, hwid, loader_version } = req.body || {};

  if (!username || !password || !hwid) {
    return res.json({ ok: false, code: "EMPTY_FIELDS" });
  }

  const users = loadUsers();
  const u = users[username];

  if (!u) {
    return res.json({ ok: false, code: "INVALID_CREDENTIALS" });
  }

  if (u.password !== password) {
    return res.json({ ok: false, code: "INVALID_CREDENTIALS" });
  }

  if (u.disabled) {
    return res.json({ ok: false, code: "DISABLED" });
  }

  // HWID logic
  if (!u.hwid) {
    // أول مرة → اربط
    u.hwid = hwid;
    users[username] = u;
    saveUsers(users);
    return res.json({
      ok: true,
      code: "BIND_OK",
      status: "Active",
      hwid_status: "Bound",
      session_token: uuidv4()
    });
  }

  if (u.hwid !== hwid) {
    return res.json({
      ok: false,
      code: "HWID_MISMATCH",
      status: "Active",
      hwid_status: "Mismatch"
    });
  }

  // كل شيء تمام
  return res.json({
    ok: true,
    code: "OK",
    status: "Active",
    hwid_status: "Bound",
    session_token: uuidv4()
  });
});

// ===================== ADMIN API =====================

// تسجيل دخول الأدمن بباس واحد (ADMIN_KEY)
app.post("/admin/login", (req, res) => {
  const { password } = req.body || {};
  if (!password || password !== ADMIN_KEY) {
    return res.json({ ok: false, code: "INVALID_ADMIN_PASSWORD" });
  }
  return res.json({ ok: true });
});

// جلب جميع المستخدمين
app.get("/admin/users", requireAdmin, (req, res) => {
  const users = loadUsers();
  const list = Object.entries(users).map(([username, data]) => ({
    username,
    password: data.password,
    hwid: data.hwid || null,
    disabled: !!data.disabled
  }));

  res.json({ ok: true, users: list });
});

// إضافة مستخدم واحد
app.post("/admin/addUser", requireAdmin, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.json({ ok: false, code: "EMPTY_FIELDS" });
  }

  const users = loadUsers();
  if (users[username]) {
    return res.json({ ok: false, code: "USER_EXISTS" });
  }

  users[username] = {
    password,
    hwid: null,
    disabled: false
  };

  saveUsers(users);
  res.json({ ok: true });
});

// إضافة كثير مره وحده (bulk) سطر لكل يوزر: username:password
app.post("/admin/addBulk", requireAdmin, (req, res) => {
  const { bulk } = req.body || {};
  if (!bulk || typeof bulk !== "string") {
    return res.json({ ok: false, code: "EMPTY_BULK" });
  }

  const users = loadUsers();
  let added = 0;
  let skipped = 0;

  bulk
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .forEach((line) => {
      const sep = line.includes("|") ? "|" : line.includes(":") ? ":" : null;
      if (!sep) {
        skipped++;
        return;
      }
      const [username, password] = line.split(sep).map((s) => s.trim());
      if (!username || !password) {
        skipped++;
        return;
      }
      if (users[username]) {
        skipped++;
        return;
      }
      users[username] = { password, hwid: null, disabled: false };
      added++;
    });

  saveUsers(users);
  res.json({ ok: true, added, skipped });
});

// حذف مستخدم
app.post("/admin/deleteUser", requireAdmin, (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.json({ ok: false, code: "EMPTY_USERNAME" });

  const users = loadUsers();
  if (!users[username]) {
    return res.json({ ok: false, code: "NOT_FOUND" });
  }

  delete users[username];
  saveUsers(users);
  res.json({ ok: true });
});

// Reset HWID
app.post("/admin/resetHwid", requireAdmin, (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.json({ ok: false, code: "EMPTY_USERNAME" });

  const users = loadUsers();
  if (!users[username]) {
    return res.json({ ok: false, code: "NOT_FOUND" });
  }

  users[username].hwid = null;
  saveUsers(users);
  res.json({ ok: true });
});

// تعطيل/تفعيل مستخدم
app.post("/admin/toggleDisable", requireAdmin, (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.json({ ok: false, code: "EMPTY_USERNAME" });

  const users = loadUsers();
  const u = users[username];
  if (!u) {
    return res.json({ ok: false, code: "NOT_FOUND" });
  }

  u.disabled = !u.disabled;
  users[username] = u;
  saveUsers(users);
  res.json({ ok: true, disabled: u.disabled });
});

// ===================== Start =====================

const PORT = process.env.PORT || 5055;
app.listen(PORT, () => {
  console.log(`Dashboard + API running on port ${PORT}`);
});
