const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
// On hosting platforms, set DATA_DIR to a persistent mounted directory (for example /data).
const DATA_DIR = process.env.DATA_DIR || ROOT;
const UPLOADS = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'nova.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  bio TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  text TEXT DEFAULT '',
  image TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS likes (
  user_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS follows (
  follower_id INTEGER NOT NULL,
  followed_id INTEGER NOT NULL,
  PRIMARY KEY(follower_id, followed_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-before-deploying-nova',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use('/uploads', express.static(UPLOADS));
app.use(express.static(path.join(ROOT, 'public')));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 10)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (/^image\/(jpeg|png|gif|webp)$/.test(file.mimetype)) return cb(null, true);
    cb(new Error('فقط فایل تصویری JPG، PNG، GIF یا WEBP مجاز است.'));
  }
});

const userPublic = u => u && ({ id: u.id, username: u.username, displayName: u.display_name, bio: u.bio || '' });
function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare('SELECT id, username, display_name, bio FROM users WHERE id = ?').get(req.session.userId) || null;
}
function auth(req, res, next) {
  if (!currentUser(req)) return res.status(401).json({ error: 'برای ادامه ابتدا وارد حساب کاربری شو.' });
  next();
}
function safePost(row, viewerId) {
  return {
    id: row.id, text: row.text, image: row.image || '', createdAt: row.created_at,
    user: { id: row.user_id, username: row.username, displayName: row.display_name, bio: row.bio || '' },
    likes: row.likes || 0, liked: !!row.liked, comments: row.comments || 0,
    isOwner: viewerId === row.user_id
  };
}

app.get('/api/me', (req, res) => res.json({ user: userPublic(currentUser(req)) }));

app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || '').trim();
  const password = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا زیرخط باشد.' });
  if (displayName.length < 2 || displayName.length > 40) return res.status(400).json({ error: 'نام نمایشی باید بین ۲ تا ۴۰ نویسه باشد.' });
  if (password.length < 8) return res.status(400).json({ error: 'رمز عبور باید حداقل ۸ نویسه داشته باشد.' });
  const hash = await bcrypt.hash(password, 12);
  try {
    const result = db.prepare('INSERT INTO users (username, display_name, password_hash) VALUES (?, ?, ?)').run(username, displayName, hash);
    req.session.userId = result.lastInsertRowid;
    res.json({ user: userPublic(currentUser(req)) });
  } catch {
    res.status(409).json({ error: 'این نام کاربری قبلاً ثبت شده است.' });
  }
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'نام کاربری یا رمز عبور درست نیست.' });
  req.session.userId = u.id;
  res.json({ user: userPublic(u) });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/posts', (req, res) => {
  const viewerId = req.session.userId || 0;
  const rows = db.prepare(`
    SELECT p.*, u.username, u.display_name, u.bio,
      (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likes,
      EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) AS liked,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comments
    FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100
  `).all(viewerId);
  res.json({ posts: rows.map(r => safePost(r, viewerId)) });
});

app.post('/api/posts', auth, upload.single('image'), (req, res) => {
  const text = String(req.body.text || '').trim();
  if (!text && !req.file) return res.status(400).json({ error: 'متن یا عکس برای انتشار وارد کن.' });
  if (text.length > 2000) return res.status(400).json({ error: 'متن پست نباید بیشتر از ۲۰۰۰ نویسه باشد.' });
  const image = req.file ? `/uploads/${req.file.filename}` : '';
  const result = db.prepare('INSERT INTO posts (user_id, text, image) VALUES (?, ?, ?)').run(req.session.userId, text, image);
  res.json({ id: result.lastInsertRowid });
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const post = db.prepare('SELECT * FROM posts WHERE id=?').get(id);
  if (!post) return res.status(404).json({ error: 'پست پیدا نشد.' });
  if (post.user_id !== req.session.userId) return res.status(403).json({ error: 'فقط صاحب پست می‌تواند آن را حذف کند.' });
  if (post.image) {
    const file = path.join(ROOT, post.image.replace(/^\//, ''));
    if (file.startsWith(UPLOADS) && fs.existsSync(file)) fs.unlinkSync(file);
  }
  db.prepare('DELETE FROM likes WHERE post_id=?').run(id);
  db.prepare('DELETE FROM comments WHERE post_id=?').run(id);
  db.prepare('DELETE FROM posts WHERE id=?').run(id);
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', auth, (req, res) => {
  const id = Number(req.params.id);
  if (!db.prepare('SELECT id FROM posts WHERE id=?').get(id)) return res.status(404).json({ error: 'پست پیدا نشد.' });
  const existing = db.prepare('SELECT 1 FROM likes WHERE user_id=? AND post_id=?').get(req.session.userId, id);
  if (existing) db.prepare('DELETE FROM likes WHERE user_id=? AND post_id=?').run(req.session.userId, id);
  else db.prepare('INSERT INTO likes (user_id, post_id) VALUES (?, ?)').run(req.session.userId, id);
  res.json({ liked: !existing });
});

app.get('/api/posts/:id/comments', (req, res) => {
  const rows = db.prepare(`SELECT c.id,c.text,c.created_at,u.username,u.display_name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id ASC`).all(Number(req.params.id));
  res.json({ comments: rows.map(c => ({ id:c.id, text:c.text, createdAt:c.created_at, user:{ username:c.username, displayName:c.display_name } })) });
});
app.post('/api/posts/:id/comments', auth, (req, res) => {
  const text = String(req.body.text || '').trim();
  if (!text || text.length > 500) return res.status(400).json({ error: 'دیدگاه باید بین ۱ تا ۵۰۰ نویسه باشد.' });
  const postId = Number(req.params.id);
  if (!db.prepare('SELECT id FROM posts WHERE id=?').get(postId)) return res.status(404).json({ error: 'پست پیدا نشد.' });
  db.prepare('INSERT INTO comments (user_id, post_id, text) VALUES (?, ?, ?)').run(req.session.userId, postId, text);
  res.json({ ok: true });
});

app.get('/api/users', auth, (req, res) => {
  const q = `%${String(req.query.q || '').trim().slice(0, 50)}%`;
  const users = db.prepare(`SELECT u.id,u.username,u.display_name,u.bio,
    EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=? AND f.followed_id=u.id) AS following
    FROM users u WHERE u.id != ? AND (u.username LIKE ? OR u.display_name LIKE ?) ORDER BY u.display_name LIMIT 30`)
    .all(req.session.userId, req.session.userId, q, q);
  res.json({ users: users.map(u => ({ ...userPublic(u), following: !!u.following })) });
});
app.get('/api/profile/:username', (req, res) => {
  const u = db.prepare(`SELECT id,username,display_name,bio,
    (SELECT COUNT(*) FROM posts WHERE user_id=users.id) AS posts,
    (SELECT COUNT(*) FROM follows WHERE followed_id=users.id) AS followers,
    (SELECT COUNT(*) FROM follows WHERE follower_id=users.id) AS following
    FROM users WHERE username=?`).get(String(req.params.username).toLowerCase());
  if (!u) return res.status(404).json({ error: 'کاربر پیدا نشد.' });
  const viewerId = req.session.userId || 0;
  const follows = viewerId ? !!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?').get(viewerId, u.id) : false;
  res.json({ profile: { ...userPublic(u), posts:u.posts, followers:u.followers, following:u.following, isMe:viewerId===u.id, follows } });
});
app.patch('/api/profile', auth, (req, res) => {
  const displayName = String(req.body.displayName || '').trim();
  const bio = String(req.body.bio || '').trim();
  if (displayName.length < 2 || displayName.length > 40) return res.status(400).json({ error: 'نام نمایشی باید بین ۲ تا ۴۰ نویسه باشد.' });
  if (bio.length > 180) return res.status(400).json({ error: 'معرفی کوتاه نباید بیشتر از ۱۸۰ نویسه باشد.' });
  db.prepare('UPDATE users SET display_name=?, bio=? WHERE id=?').run(displayName, bio, req.session.userId);
  res.json({ user:userPublic(currentUser(req)) });
});
app.post('/api/users/:id/follow', auth, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.session.userId) return res.status(400).json({ error: 'نمی‌توانی خودت را دنبال کنی.' });
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(id)) return res.status(404).json({ error: 'کاربر پیدا نشد.' });
  const exists = db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?').get(req.session.userId,id);
  if (exists) db.prepare('DELETE FROM follows WHERE follower_id=? AND followed_id=?').run(req.session.userId,id);
  else db.prepare('INSERT INTO follows (follower_id,followed_id) VALUES (?,?)').run(req.session.userId,id);
  res.json({ following:!exists });
});

app.get('/api/conversations', auth, (req, res) => {
  const uid = req.session.userId;
  const rows = db.prepare(`SELECT u.id,u.username,u.display_name,
    (SELECT text FROM messages m WHERE (m.sender_id=uid AND m.receiver_id=u.id) OR (m.sender_id=u.id AND m.receiver_id=uid) ORDER BY m.id DESC LIMIT 1) AS last_message,
    (SELECT MAX(id) FROM messages m WHERE (m.sender_id=uid AND m.receiver_id=u.id) OR (m.sender_id=u.id AND m.receiver_id=uid)) AS last_id
    FROM users u WHERE u.id != uid AND EXISTS(SELECT 1 FROM messages m WHERE (m.sender_id=uid AND m.receiver_id=u.id) OR (m.sender_id=u.id AND m.receiver_id=uid))
    ORDER BY last_id DESC`).all();
  res.json({ conversations:rows.map(u=>({id:u.id,username:u.username,displayName:u.display_name,lastMessage:u.last_message})) });
});
app.get('/api/messages/:userId', auth, (req, res) => {
  const other = Number(req.params.userId), uid = req.session.userId;
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(other)) return res.status(404).json({ error: 'کاربر پیدا نشد.' });
  const messages = db.prepare(`SELECT id,sender_id,receiver_id,text,created_at FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY id ASC LIMIT 200`).all(uid,other,other,uid);
  res.json({ messages:messages.map(m=>({id:m.id,senderId:m.sender_id,receiverId:m.receiver_id,text:m.text,createdAt:m.created_at,mine:m.sender_id===uid})) });
});
app.post('/api/messages/:userId', auth, (req, res) => {
  const other = Number(req.params.userId), text = String(req.body.text || '').trim();
  if (!text || text.length > 2000) return res.status(400).json({ error: 'پیام باید بین ۱ تا ۲۰۰۰ نویسه باشد.' });
  if (other === req.session.userId || !db.prepare('SELECT id FROM users WHERE id=?').get(other)) return res.status(404).json({ error: 'گیرنده معتبر نیست.' });
  db.prepare('INSERT INTO messages (sender_id,receiver_id,text) VALUES (?,?,?)').run(req.session.userId,other,text);
  res.json({ ok:true });
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'حجم عکس باید کمتر از ۵ مگابایت باشد.' : 'بارگذاری فایل ناموفق بود.' });
  res.status(400).json({ error: err.message || 'خطایی رخ داد.' });
});
app.listen(PORT, '0.0.0.0', () => console.log(`نُوا اجرا شد روی درگاه ${PORT}`));
