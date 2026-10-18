
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || ROOT;
const UPLOADS = path.join(DATA_DIR, 'uploads');

fs.mkdirSync(UPLOADS, { recursive: true });

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL تنظیم نشده است.');
  process.exit(1);
}

if (!process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET تنظیم نشده است.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.on('error', err => {
  console.error('خطای اتصال پایگاه داده:', err.message);
});

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.get('/healthz', (_req, res) => {
  res.status(200).send('ok');
});

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
    if (/^image\/(jpeg|png|gif|webp)$/.test(file.mimetype)) {
      return cb(null, true);
    }
    cb(new Error('فقط فایل تصویری JPG، PNG، GIF یا WEBP مجاز است.'));
  }
});

const userPublic = u => u && ({
  id: u.id,
  username: u.username,
  displayName: u.display_name,
  bio: u.bio || ''
});

async function currentUser(req) {
  if (!req.session.userId) return null;

  const result = await pool.query(
    'SELECT id, username, display_name, bio FROM users WHERE id = $1',
    [req.session.userId]
  );

  return result.rows[0] || null;
}

const auth = asyncRoute(async (req, res, next) => {
  if (!await currentUser(req)) {
    return res.status(401).json({
      error: 'برای ادامه ابتدا وارد حساب کاربری شو.'
    });
  }
  next();
});

function safePost(row, viewerId) {
  return {
    id: row.id,
    text: row.text,
    image: row.image || '',
    createdAt: row.created_at,
    user: {
      id: row.user_id,
      username: row.username,
      displayName: row.display_name,
      bio: row.bio || ''
    },
    likes: Number(row.likes || 0),
    liked: !!row.liked,
    comments: Number(row.comments || 0),
    isOwner: viewerId === row.user_id
  };
}

app.get('/api/me', asyncRoute(async (req, res) => {
  res.json({ user: userPublic(await currentUser(req)) });
}));

app.post('/api/register', asyncRoute(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || '').trim();
  const password = String(req.body.password || '');

  if (!/^[a-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({
      error: 'نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا زیرخط باشد.'
    });
  }

  if (displayName.length < 2 || displayName.length > 40) {
    return res.status(400).json({
      error: 'نام نمایشی باید بین ۲ تا ۴۰ نویسه باشد.'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: 'رمز عبور باید حداقل ۸ نویسه داشته باشد.'
    });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = await pool.query(
      'INSERT INTO users (username, display_name, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [username, displayName, hash]
    );

    req.session.userId = result.rows[0].id;
    res.json({ user: userPublic(await currentUser(req)) });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({
        error: 'این نام کاربری قبلاً ثبت شده است.'
      });
    }
    throw err;
  }
}));

app.post('/api/login', asyncRoute(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
  );

  const u = result.rows[0];

  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    return res.status(401).json({
      error: 'نام کاربری یا رمز عبور درست نیست.'
    });
  }

  req.session.userId = u.id;
  res.json({ user: userPublic(u) });
}));

app.post('/api/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.json({ ok: true });
  });
});

app.get('/api/posts', asyncRoute(async (req, res) => {
  const viewerId = req.session.userId || 0;

  const result = await pool.query(`
    SELECT p.*, u.username, u.display_name, u.bio,
      (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likes,
      EXISTS(
        SELECT 1 FROM likes l
        WHERE l.post_id = p.id AND l.user_id = $1
      ) AS liked,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments
    FROM posts p
    JOIN users u ON u.id = p.user_id
    ORDER BY p.id DESC
    LIMIT 100
  `, [viewerId]);

  res.json({ posts: result.rows.map(r => safePost(r, viewerId)) });
}));

app.post('/api/posts', auth, upload.single('image'), asyncRoute(async (req, res) => {
  const text = String(req.body.text || '').trim();

  if (!text && !req.file) {
    return res.status(400).json({
      error: 'متن یا عکس برای انتشار وارد کن.'
    });
  }

  if (text.length > 2000) {
    return res.status(400).json({
      error: 'متن پست نباید بیشتر از ۲۰۰۰ نویسه باشد.'
    });
  }

  const image = req.file ? `/uploads/${req.file.filename}` : '';

  const result = await pool.query(
    'INSERT INTO posts (user_id, text, image) VALUES ($1, $2, $3) RETURNING id',
    [req.session.userId, text, image]
  );

  res.json({ id: result.rows[0].id });
}));

app.delete('/api/posts/:id', auth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: 'شناسه پست معتبر نیست.' });
  }

  const result = await pool.query(
    'SELECT * FROM posts WHERE id = $1',
    [id]
  );

  const post = result.rows[0];

  if (!post) {
    return res.status(404).json({ error: 'پست پیدا نشد.' });
  }

  if (post.user_id !== req.session.userId) {
    return res.status(403).json({
      error: 'فقط صاحب پست می‌تواند آن را حذف کند.'
    });
  }

  await pool.query('DELETE FROM likes WHERE post_id = $1', [id]);
  await pool.query('DELETE FROM comments WHERE post_id = $1', [id]);
  await pool.query('DELETE FROM posts WHERE id = $1', [id]);

  if (post.image) {
    const filename = path.basename(post.image);
    const file = path.join(UPLOADS, filename);

    if (fs.existsSync(file)) fs.unlinkSync(file);
  }

  res.json({ ok: true });
}));

app.post('/api/posts/:id/like', auth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);

  const post = await pool.query(
    'SELECT id FROM posts WHERE id = $1',
    [id]
  );

  if (!post.rows.length) {
    return res.status(404).json({ error: 'پست پیدا نشد.' });
  }

  const existing = await pool.query(
    'SELECT 1 FROM likes WHERE user_id = $1 AND post_id = $2',
    [req.session.userId, id]
  );

  if (existing.rows.length) {
    await pool.query(
      'DELETE FROM likes WHERE user_id = $1 AND post_id = $2',
      [req.session.userId, id]
    );
  } else {
    await pool.query(
      'INSERT INTO likes (user_id, post_id) VALUES ($1, $2)',
      [req.session.userId, id]
    );
  }

  res.json({ liked: !existing.rows.length });
}));

app.get('/api/posts/:id/comments', asyncRoute(async (req, res) => {
  const result = await pool.query(`
    SELECT c.id, c.text, c.created_at, u.username, u.display_name
    FROM comments c
    JOIN users u ON u.id = c.user_id
    WHERE c.post_id = $1
    ORDER BY c.id ASC
  `, [Number(req.params.id)]);

  res.json({
    comments: result.rows.map(c => ({
      id: c.id,
      text: c.text,
      createdAt: c.created_at,
      user: {
        username: c.username,
        displayName: c.display_name
      }
    }))
  });
}));

app.post('/api/posts/:id/comments', auth, asyncRoute(async (req, res) => {
  const text = String(req.body.text || '').trim();

  if (!text || text.length > 500) {
    return res.status(400).json({
      error: 'دیدگاه باید بین ۱ تا ۵۰۰ نویسه باشد.'
    });
  }

  const postId = Number(req.params.id);
  const post = await pool.query(
    'SELECT id FROM posts WHERE id = $1',
    [postId]
  );

  if (!post.rows.length) {
    return res.status(404).json({ error: 'پست پیدا نشد.' });
  }

  await pool.query(
    'INSERT INTO comments (user_id, post_id, text) VALUES ($1, $2, $3)',
    [req.session.userId, postId, text]
  );

  res.json({ ok: true });
}));

app.get('/api/users', auth, asyncRoute(async (req, res) => {
  const q = `%${String(req.query.q || '').trim().slice(0, 50)}%`;

  const result = await pool.query(`
    SELECT u.id, u.username, u.display_name, u.bio,
      EXISTS(
        SELECT 1 FROM follows f
        WHERE f.follower_id = $1 AND f.followed_id = u.id
      ) AS following
    FROM users u
    WHERE u.id <> $1
      AND (u.username ILIKE $2 OR u.display_name ILIKE $2)
    ORDER BY u.display_name
    LIMIT 30
  `, [req.session.userId, q]);

  res.json({
    users: result.rows.map(u => ({
      ...userPublic(u),
      following: !!u.following
    }))
  });
}));

app.get('/api/profile/:username', asyncRoute(async (req, res) => {
  const result = await pool.query(`
    SELECT id, username, display_name, bio,
      (SELECT COUNT(*) FROM posts WHERE user_id = users.id) AS posts,
      (SELECT COUNT(*) FROM follows WHERE followed_id = users.id) AS followers,
      (SELECT COUNT(*) FROM follows WHERE follower_id = users.id) AS following
    FROM users
    WHERE username = $1
  `, [String(req.params.username).toLowerCase()]);

  const u = result.rows[0];

  if (!u) {
    return res.status(404).json({ error: 'کاربر پیدا نشد.' });
  }

  const viewerId = req.session.userId || 0;
  let follows = false;

  if (viewerId) {
    const followResult = await pool.query(
      'SELECT 1 FROM follows WHERE follower_id = $1 AND followed_id = $2',
      [viewerId, u.id]
    );
    follows = followResult.rows.length > 0;
  }

  res.json({
    profile: {
      ...userPublic(u),
      posts: Number(u.posts),
      followers: Number(u.followers),
      following: Number(u.following),
      isMe: viewerId === u.id,
      follows
    }
  });
}));

app.patch('/api/profile', auth, asyncRoute(async (req, res) => {
  const displayName = String(req.body.displayName || '').trim();
  const bio = String(req.body.bio || '').trim();

  if (displayName.length < 2 || displayName.length > 40) {
    return res.status(400).json({
      error: 'نام نمایشی باید بین ۲ تا ۴۰ نویسه باشد.'
    });
  }

  if (bio.length > 180) {
    return res.status(400).json({
      error: 'معرفی کوتاه نباید بیشتر از ۱۸۰ نویسه باشد.'
    });
  }

  await pool.query(
    'UPDATE users SET display_name = $1, bio = $2 WHERE id = $3',
    [displayName, bio, req.session.userId]
  );

  res.json({ user: userPublic(await currentUser(req)) });
}));

app.post('/api/users/:id/follow', auth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);

  if (id === req.session.userId) {
    return res.status(400).json({
      error: 'نمی‌توانی خودت را دنبال کنی.'
    });
  }

  const user = await pool.query(
    'SELECT id FROM users WHERE id = $1',
    [id]
  );

  if (!user.rows.length) {
    return res.status(404).json({ error: 'کاربر پیدا نشد.' });
  }

  const existing = await pool.query(
    'SELECT 1 FROM follows WHERE follower_id = $1 AND followed_id = $2',
    [req.session.userId, id]
  );

  if (existing.rows.length) {
    await pool.query(
      'DELETE FROM follows WHERE follower_id = $1 AND followed_id = $2',
      [req.session.userId, id]
    );
  } else {
    await pool.query(
      'INSERT INTO follows (follower_id, followed_id) VALUES ($1, $2)',
      [req.session.userId, id]
    );
  }

  res.json({ following: !existing.rows.length });
}));

app.get('/api/conversations', auth, asyncRoute(async (req, res) => {
  const uid = req.session.userId;

  const result = await pool.query(`
    SELECT u.id, u.username, u.display_name,
      (
        SELECT text FROM messages m
        WHERE (m.sender_id = $1 AND m.receiver_id = u.id)
           OR (m.sender_id = u.id AND m.receiver_id = $1)
        ORDER BY m.id DESC
        LIMIT 1
      ) AS last_message,
      (
        SELECT MAX(id) FROM messages m
        WHERE (m.sender_id = $1 AND m.receiver_id = u.id)
           OR (m.sender_id = u.id AND m.receiver_id = $1)
      ) AS last_id
    FROM users u
    WHERE u.id <> $1
      AND EXISTS (
        SELECT 1 FROM messages m
        WHERE (m.sender_id = $1 AND m.receiver_id = u.id)
           OR (m.sender_id = u.id AND m.receiver_id = $1)
      )
    ORDER BY last_id DESC
  `, [uid]);

  res.json({
    conversations: result.rows.map(u => ({
      id: u.id,
      username: u.username,
      displayName: u.display_name,
      lastMessage: u.last_message
    }))
  });
}));

app.get('/api/messages/:userId', auth, asyncRoute(async (req, res) => {
  const other = Number(req.params.userId);
  const uid = req.session.userId;

  const user = await pool.query(
    'SELECT id FROM users WHERE id = $1',
    [other]
  );

  if (!user.rows.length) {
    return res.status(404).json({ error: 'کاربر پیدا نشد.' });
  }

  const result = await pool.query(`
    SELECT id, sender_id, receiver_id, text, created_at
    FROM messages
    WHERE (sender_id = $1 AND receiver_id = $2)
       OR (sender_id = $2 AND receiver_id = $1)
    ORDER BY id ASC
    LIMIT 200
  `, [uid, other]);

  res.json({
    messages: result.rows.map(m => ({
      id: m.id,
      senderId: m.sender_id,
      receiverId: m.receiver_id,
      text: m.text,
      createdAt: m.created_at,
      mine: m.sender_id === uid
    }))
  });
}));

app.post('/api/messages/:userId', auth, asyncRoute(async (req, res) => {
  const other = Number(req.params.userId);
  const text = String(req.body.text || '').trim();

  if (!text || text.length > 2000) {
    return res.status(400).json({
      error: 'پیام باید بین ۱ تا ۲۰۰۰ نویسه باشد.'
    });
  }

  if (other === req.session.userId) {
    return res.status(400).json({
      error: 'نمی‌توانی به خودت پیام بدهی.'
    });
  }

  const user = await pool.query(
    'SELECT id FROM users WHERE id = $1',
    [other]
  );

  if (!user.rows.length) {
    return res.status(404).json({ error: 'گیرنده معتبر نیست.' });
  }

  await pool.query(
    'INSERT INTO messages (sender_id, receiver_id, text) VALUES ($1, $2, $3)',
    [req.session.userId, other, text]
  );

  res.json({ ok: true });
}));

app.use((err, _req, res, _next) => {
  console.error(err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: err.code === 'LIMIT_FILE_SIZE'
        ? 'حجم عکس باید کمتر از ۵ مگابایت باشد.'
        : 'بارگذاری فایل ناموفق بود.'
    });
  }

  res.status(500).json({
    error: 'خطایی در سرور رخ داد. لطفاً دوباره تلاش کن.'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`نُوا اجرا شد روی درگاه ${PORT}`);
});
  
