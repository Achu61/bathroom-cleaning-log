const express = require("express"), Database = require("better-sqlite3"), bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"), cookieParser = require("cookie-parser"), fs = require("fs"), path = require("path"), crypto = require("crypto");

const DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DIR, { recursive: true });
const db = new Database(path.join(DIR, "app.db"));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT, role TEXT, hash TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS logs(rowid INTEGER PRIMARY KEY AUTOINCREMENT, bid TEXT, bname TEXT, blk TEXT, uid TEXT, uname TEXT, status TEXT, note TEXT, ts INTEGER);
CREATE INDEX IF NOT EXISTS i_logs_ts ON logs(ts);`);

// Secret for login cookies (set SECRET in the environment, or one is generated and kept in data/)
let SECRET = process.env.SECRET;
if (!SECRET) {
  const f = path.join(DIR, "secret.txt");
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString("hex"));
  SECRET = fs.readFileSync(f, "utf8");
}

// ---- Bathroom list (edit here to add or rename bathrooms) ----
const NEW = ["Ground – Central Toilet", "2nd NHDU", "Cardiac Ward", "Dialysis", "5 B wing – Cubicle 2525–29", "5 B wing – Cubicle 2530–34", "5 B wing – Cubicle 2545–49"];
for (const l of "ABCDEF") NEW.push("6 B wing – Cubicle " + l);
for (const l of "ABCDEF") NEW.push("7 B wing – Cubicle " + l);
const OLD = ["Ground – Central", "ED near Pharmacy", "ED inside", "Acute 1", "Oncology Ground", "Oncology First", "Khaleej Ground", "Daycare 1", "Daycare 2", "Nuclear", "1st Floor – Central", "1st Floor – Lab", "Gynec", "Counter 1", "Ortho", "ENT", "Xray", "Procedure OPD", "USG", "Counter 5", "2nd Floor – Central", "2nd Floor – Lab", "Administration", "Cardiac OP", "3rd Floor – Central Toilet", "4th – Colonoscopy", "4th – Day surgery"];
const BATH = [
  ...NEW.map((name, i) => ({ id: "N-" + String(i + 1).padStart(2, "0"), name, blk: "New Block" })),
  ...OLD.map((name, i) => ({ id: "O-" + String(i + 1).padStart(2, "0"), name, blk: "Old Block" })),
];
const BY_ID = Object.fromEntries(BATH.map(b => [b.id, b]));

const app = express();
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const userCount = () => db.prepare("SELECT COUNT(*) c FROM users").get().c;
const publicUser = u => u && { id: u.id, name: u.name, role: u.role };
function auth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.session, SECRET);
    const u = db.prepare("SELECT * FROM users WHERE id=?").get(p.id);
    if (!u) throw 0;
    req.user = u; next();
  } catch (e) { res.status(401).json({ error: "Please sign in." }); }
}
const adminOnly = (req, res, next) => req.user.role === "admin" ? next() : res.status(403).json({ error: "Admin only." });
function setSession(res, id) {
  res.cookie("session", jwt.sign({ id }, SECRET, { expiresIn: "30d" }), { httpOnly: true, sameSite: "lax", maxAge: 30 * 864e5, secure: process.env.COOKIE_SECURE === "1" });
}

// Simple brute-force guard: 10 failed logins per 10 minutes per IP
const fails = new Map();
const blocked = ip => (fails.get(ip) || []).filter(t => Date.now() - t < 6e5).length >= 10;

app.get("/api/bathrooms", (req, res) => res.json(BATH));
app.get("/api/me", (req, res) => {
  let user = null;
  try { user = publicUser(db.prepare("SELECT * FROM users WHERE id=?").get(jwt.verify(req.cookies.session, SECRET).id)); } catch (e) {}
  res.json({ needsSetup: userCount() === 0, user });
});
app.post("/api/setup", async (req, res) => {
  if (userCount() > 0) return res.status(403).json({ error: "Already set up." });
  const { id = "", name = "", pw = "" } = req.body, uid = id.trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,}$/.test(uid) || pw.length < 6) return res.status(400).json({ error: "ID needs 3+ letters or digits; password 6+ characters." });
  db.prepare("INSERT INTO users VALUES(?,?,?,?,?)").run(uid, name.trim() || uid, "admin", await bcrypt.hash(pw, 10), Date.now());
  setSession(res, uid); res.json({ ok: true });
});
app.post("/api/login", async (req, res) => {
  if (blocked(req.ip)) return res.status(429).json({ error: "Too many attempts. Try again later." });
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(String(req.body.id || "").trim().toLowerCase());
  if (!u || !(await bcrypt.compare(String(req.body.pw || ""), u.hash))) {
    fails.set(req.ip, [...(fails.get(req.ip) || []), Date.now()]);
    return res.status(401).json({ error: "Wrong ID or password." });
  }
  setSession(res, u.id); res.json({ user: publicUser(u) });
});
app.post("/api/logout", (req, res) => { res.clearCookie("session"); res.json({ ok: true }); });

// Record a cleaning. The date and time come from the SERVER clock, not the phone.
app.post("/api/log", auth, (req, res) => {
  const b = BY_ID[req.body.bid];
  const status = req.body.status;
  if (!b || !["cleaned", "not cleaned"].includes(status)) return res.status(400).json({ error: "Invalid entry." });
  const ts = Date.now();
  db.prepare("INSERT INTO logs(bid,bname,blk,uid,uname,status,note,ts) VALUES(?,?,?,?,?,?,?,?)")
    .run(b.id, b.name, b.blk, req.user.id, req.user.name, status, String(req.body.note || "").slice(0, 300), ts);
  res.json({ ok: true, ts, bname: b.name });
});
app.get("/api/logs", auth, (req, res) => {
  if (req.user.role === "admin") return res.json(db.prepare("SELECT * FROM logs ORDER BY ts DESC LIMIT 5000").all());
  res.json(db.prepare("SELECT * FROM logs WHERE uid=? ORDER BY ts DESC LIMIT 8").all(req.user.id));
});
app.get("/api/last", auth, adminOnly, (req, res) =>
  res.json(db.prepare("SELECT * FROM logs WHERE rowid IN (SELECT MAX(rowid) FROM logs GROUP BY bid)").all()));

app.get("/api/users", auth, adminOnly, (req, res) => res.json(db.prepare("SELECT id,name,role FROM users ORDER BY id").all()));
app.post("/api/users", auth, adminOnly, async (req, res) => {
  const { id = "", name = "", pw = "", role = "cleaner" } = req.body, uid = id.trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,}$/.test(uid) || pw.length < 6 || !["cleaner", "admin"].includes(role)) return res.status(400).json({ error: "ID: 3+ letters or digits (no spaces). Password: 6+ characters." });
  if (db.prepare("SELECT 1 FROM users WHERE id=?").get(uid)) return res.status(409).json({ error: "That ID is already used." });
  db.prepare("INSERT INTO users VALUES(?,?,?,?,?)").run(uid, name.trim() || uid, role, await bcrypt.hash(pw, 10), Date.now());
  res.json({ ok: true });
});
app.post("/api/users/:id/password", auth, adminOnly, async (req, res) => {
  if (String(req.body.pw || "").length < 6) return res.status(400).json({ error: "Password: 6+ characters." });
  db.prepare("UPDATE users SET hash=? WHERE id=?").run(await bcrypt.hash(req.body.pw, 10), req.params.id); res.json({ ok: true });
});
app.delete("/api/users/:id", auth, adminOnly, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "You cannot remove yourself." });
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id); res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log("Bathroom Cleaning Log running on http://localhost:" + PORT));
