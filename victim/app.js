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
    { id: 1, username: "admin", passwordHash: bcrypt.hashSync("admin", 10) },
    { id: 2, username: "au", passwordHash: bcrypt.hashSync("au", 10) },

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


let inboxMessages = [

    {
        id: 1,
        title: "ยืนยันการสมัครกิจกรรม Open House",
        from: "ฝ่ายกิจกรรม",
        createdAt: "2026-02-19 16:20",
        unread: true,
        imageUrl: "https://picsum.photos/seed/openhouse/240/160",
        body: `...`,
    },

    {
        id: 2,
        title: "แจ้งกำหนดการชำระค่าธรรมเนียม ภาคเรียนที่ 1/2568",
        from: "สมชาติ์ ศรีสุวรรณ",
        createdAt: "2026-02-22 08:45",
        unread: true,
        imageUrl: "https://picsum.photos/seed/fee1/240/160",
        body: `...`,
    },

    {
        id:3,
        title: "ผลการลงทะเบียนสำเร็จ",
        from: "ระบบทะเบียน",
        createdAt: "2026-02-20 14:05",
        unread: false,
        imageUrl: "https://picsum.photos/seed/success/240/160",
        body: `...`,
    },
    {
        id: 4,
        title: "แจ้งเตือน: เปลี่ยนรหัสผ่านด่วน",
        from: "security-alert@university.ac.th",
        createdAt: "2026-02-20 09:15",
        unread: false,
        imageUrl: "https://picsum.photos/seed/security1/240/160",
        body: `...`,
    },
    {
        id: 5,
        title: "ประกาศ: ปรับปรุงระบบช่วงเวลา 23:00-01:00",
        from: "แสวง บุญมี",
        createdAt: "2026-02-21 18:30",
        unread: false,
        imageUrl: "https://picsum.photos/seed/maintenance/240/160",
        body: `...`,
    },

    {
        id: 6,
        title: "แจ้งผลการพิจารณาทุนการศึกษา",
        from: "กองทุนการศึกษา",
        createdAt: "2026-02-19 10:12",
        unread: false,
        imageUrl: "https://picsum.photos/seed/scholarship/240/160",
        body: `...`,
    },
    {
        id: 7,
        title: "ตารางสอบกลางภาค ภาคเรียนที่ 1/2568",
        from: "ฝ่ายวิชาการ",
        createdAt: "2026-02-18 13:40",
        unread: false,
        imageUrl: "https://picsum.photos/seed/exam/240/160",
        body: `...`,
    }


];


// make user available in views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// ✅ unreadCount must come AFTER inboxMessages is defined
app.use((req, res, next) => {
  if (!req.session.user) {
    res.locals.unreadCount = 0;
    return next();
  }
  res.locals.unreadCount = inboxMessages.filter((m) => m.unread).length;
  next();
});

function nextInboxId() {
  const maxId = inboxMessages.reduce((mx, m) => Math.max(mx, m.id), 0);
  return maxId + 1;
}

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



// ===== inbox: random generator + in-memory store =====


// ===== inbox routes =====
app.get("/inbox", requireAuth, (req, res) => {
    const items = [...inboxMessages]; // already sorted newest first
    const unreadCount = items.filter((m) => m.unread).length;

    res.render("inbox", { items, unreadCount });
});

app.get("/inbox/:id", requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const msg = inboxMessages.find((m) => m.id === id);
    if (!msg) return res.status(404).send("Message not found");

    if (msg.unread) {
        msg.unread = false;
        msg.readAt = new Date().toISOString().replace("T", " ").slice(0, 16);
    }

    res.render("inbox-read", { msg });
});




// ✅ GET /announcements = หน้า "สร้างข้อความ"
app.get("/announcements", requireAuth, (req, res) => {
  res.render("announcements-new", {
    error: null,
    active: "announcements",
  });
});

// ✅ POST /announcements = สร้างข้อความ (เข้า inbox)
app.post("/announcements", requireAuth, (req, res) => {
  const { title, body, imageUrl } = req.body;

  if (!title || String(title).trim().length < 3) {
    return res.status(400).render("announcements-new", {
      error: "หัวข้อต้องยาวอย่างน้อย 3 ตัวอักษร",
      active: "announcements",
    });
  }

  const now = new Date().toISOString().replace("T", " ").slice(0, 16);

  const msg = {
    id: nextInboxId(),
    title: String(title).trim(),
    from: req.session.user.username,
    createdAt: now,
    unread: true,
    imageUrl: imageUrl && String(imageUrl).trim() ? String(imageUrl).trim() : null,
    body: body ? String(body) : "",
  };

  inboxMessages.unshift(msg);
  return res.redirect("/inbox");
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
        console.log("Demo user: admin / admin");
        console.log("Demo user: au / au");
    });