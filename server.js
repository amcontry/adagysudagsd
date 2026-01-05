const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();
const db = new sqlite3.Database("./db.sqlite");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: "secure-doc-portal",
    resave: false,
    saveUninitialized: false,
  })
);

/* ===== DB 초기화 ===== */
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT,
      level TEXT,
      author TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.get("SELECT * FROM users WHERE username='admin'", async (_, row) => {
    if (!row) {
      const hash = await bcrypt.hash("admin123", 10);
      db.run(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ["admin", hash, "admin"]
      );
      console.log("✔ admin 계정 생성됨 (admin / admin123)");
    }
  });
});

/* ===== AUTH ===== */
function auth(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.sendStatus(403);
    if (role && req.session.user.role !== role) return res.sendStatus(403);
    next();
  };
}

/* ===== LOGIN ===== */
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (_, user) => {
    if (!user) return res.sendStatus(401);
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.sendStatus(401);

    req.session.user = { username: user.username, role: user.role };
    res.json({ role: user.role });
  });
});

/* ===== USER MANAGEMENT ===== */
app.post("/admin/create", auth("admin"), async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.sendStatus(400);
  const hash = await bcrypt.hash(password, 10);
  db.run(
    "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
    [username, hash],
    err => err ? res.sendStatus(400) : res.sendStatus(200)
  );
});

app.post("/admin/delete", auth("admin"), (req, res) => {
  const { username } = req.body;
  if (!username) return res.sendStatus(400);
  db.run("DELETE FROM users WHERE username=?", [username], () => res.sendStatus(200));
});

/* ===== DOCUMENTS ===== */
app.post("/docs", auth(), (req, res) => {
  const { title, content, level } = req.body;
  const author = req.session.user.username;
  if (!title || !content || !level) return res.sendStatus(400);

  db.run(
    "INSERT INTO documents (title, content, level, author) VALUES (?, ?, ?, ?)",
    [title, content, level, author],
    err => err ? res.sendStatus(500) : res.sendStatus(200)
  );
});

app.get("/docs", auth(), (_, res) => {
  db.all("SELECT * FROM documents ORDER BY created_at DESC", (_, rows) => res.json(rows));
});

app.post("/docs/delete", auth(), (req, res) => {
  const { id } = req.body;
  if (!id) return res.sendStatus(400);

  db.run(
    "DELETE FROM documents WHERE id=? AND author=?",
    [id, req.session.user.username],
    function () {
      this.changes ? res.sendStatus(200) : res.sendStatus(403);
    }
  );
});

app.get("/docs/search", auth(), (req, res) => {
  const q = `%${req.query.q}%`;
  db.all(
    "SELECT * FROM documents WHERE title LIKE ? OR content LIKE ? ORDER BY created_at DESC",
    [q, q],
    (_, rows) => res.json(rows)
  );
});

app.listen(3000, () => console.log("▶ Secure Portal running: http://localhost:3000"));
