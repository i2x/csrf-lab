const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const https = require("https");
const fs = require("fs");
const path = require("path");

const app = express();

// ===== simple in-memory "DB" =====
const users = [
  // demo user: alice / password123
  { id: 1, username: "alice", passwordHash: bcrypt.hashSync("password123", 10) },
];

function findUser(username) {
  return users.find((u) => u.username === username);
}
function updatePassword(userId, newHash) {
  const u = users.find((x) => x.id === userId);
  if (u) u.passwordHash = newHash;
}

// ===== app setup =====
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// IMPORTANT: trust proxy is NOT needed here (direct https server)
// app.set("trust proxy", 1);

app.use(
  session({
    name: "sid",
    secret: "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,      // ✅ ต้อง true เพราะเราจะใช้ https
      sameSite: "none",  // ✅ ต้อง none เพื่อให้ข้ามไซต์ (attacker) ส่งคุกกี้ได้
      maxAge: 1000 * 60 * 60,
    },
  })
);

// make user available in views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

// ===== routes =====
app.get("/", (req, res) => res.redirect("/main"));

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const u = findUser(username);
  if (!u) return res.status(401).render("login", { error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(401).render("login", { error: "Invalid credentials" });

  req.session.user = { id: u.id, username: u.username };
  res.redirect("/main");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/main", requireAuth, (req, res) => {
  res.render("main");
});

// หน้าเปลี่ยนรหัส (ไว้ดูผล)
app.get("/change-password", requireAuth, (req, res) => {
  res.render("change-password", { error: null, success: null });
});

/**
 * ✅ Vulnerable GET endpoint (สำหรับ CSRF demo)
 * - ใช้ GET เปลี่ยนรหัสผ่าน (ผิดหลัก)
 * - ไม่มี CSRF token
 * - ไม่ต้องรหัสเดิม
 * - แค่ user ล็อกอินค้างไว้ => attacker ยิงได้
 *
 * ใช้: /change-password-unsafe?newPassword=999999
 */
app.get("/change-password-unsafe", requireAuth, async (req, res) => {
  const { newPassword } = req.query;

  if (!newPassword || String(newPassword).length < 4) {
    return res.status(400).render("change-password", {
      error: "Password must be at least 4 characters",
      success: null,
    });
  }

  const userId = req.session.user.id;
  const newHash = await bcrypt.hash(String(newPassword), 10);
  updatePassword(userId, newHash);

  res.render("change-password", {
    error: null,
    success: `Password changed to "${newPassword}" (demo)!`,
  });
});

// ===== https server =====
const keyPath = path.join(__dirname, "cert", "localhost-key.pem");
const certPath = path.join(__dirname, "cert", "localhost.pem");

https
  .createServer(
    {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    },
    app
  )
  .listen(3000, () => {
    console.log("Victim running on https://localhost:3000");
    console.log("Demo user: alice / password123");
    console.log("Unsafe endpoint: https://localhost:3000/change-password-unsafe?newPassword=999999");
  });