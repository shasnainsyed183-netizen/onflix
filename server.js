const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const uuidv4 = () => crypto.randomUUID();
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ==================== CONFIG ====================
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://onflix-production.up.railway.app';
const ADMIN_DEVICE_KEY = process.env.ADMIN_DEVICE_KEY || 'onflix_admin_master_key_2025';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Shash@123';
let adminPasswordHash = null;

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/posters', express.static('posters'));
app.use(session({ secret: JWT_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// ==================== DATABASE ====================
const DB = 'movies.json';
const USERS_DB = 'users.json';
const ACTIVITY_DB = 'activity.json';
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('posters')) fs.mkdirSync('posters');
if (!fs.existsSync(DB)) fs.writeFileSync(DB, '[]');
if (!fs.existsSync(USERS_DB)) fs.writeFileSync(USERS_DB, '[]');
if (!fs.existsSync(ACTIVITY_DB)) fs.writeFileSync(ACTIVITY_DB, '[]');

const getMovies = () => JSON.parse(fs.readFileSync(DB));
const saveMovies = (m) => fs.writeFileSync(DB, JSON.stringify(m, null, 2));
const getUsers = () => JSON.parse(fs.readFileSync(USERS_DB));
const saveUsers = (u) => fs.writeFileSync(USERS_DB, JSON.stringify(u, null, 2));
const getActivity = () => JSON.parse(fs.readFileSync(ACTIVITY_DB));
const saveActivity = (a) => fs.writeFileSync(ACTIVITY_DB, JSON.stringify(a, null, 2));

function logActivity(userId, action, details = '') {
    const activities = getActivity();
    activities.push({ userId, action, details, timestamp: new Date().toISOString() });
    if (activities.length > 1000) activities.splice(0, activities.length - 1000);
    saveActivity(activities);
}

// ==================== INIT ADMIN ====================
async function initAdmin() {
    if (!adminPasswordHash) adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
}
initAdmin();

// ==================== STORAGE ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'poster') cb(null, 'posters/');
        else cb(null, 'uploads/');
    },
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

// ==================== PASSPORT GOOGLE ====================
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL + '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    const users = getUsers();
    let user = users.find(u => u.email === profile.emails[0].value);
    if (!user) {
        user = { id: uuidv4(), name: profile.displayName, email: profile.emails[0].value, avatar: profile.photos?.[0]?.value || '', googleId: profile.id, provider: 'google', createdAt: new Date().toISOString(), lastLogin: new Date().toISOString() };
        users.push(user); saveUsers(users);
        logActivity(user.id, 'signup', 'Google signup');
    } else {
        user.lastLogin = new Date().toISOString();
        saveUsers(users);
        logActivity(user.id, 'login', 'Google login');
    }
    return done(null, user);
}));
passport.serializeUser((u, d) => d(null, u.id));
passport.deserializeUser((id, d) => { d(null, getUsers().find(u => u.id === id)); });

// ==================== AUTH MIDDLEWARE ====================
function authRequired(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (req.isAuthenticated?.()) return next();
    if (token) { try { req.user = jwt.verify(token, JWT_SECRET); return next(); } catch(e) {} }
    return res.status(401).json({ error: 'Please login first' });
}

async function requireAdmin(req, res, next) {
    const password = req.headers['x-admin-password'] || req.query.password;
    const deviceKey = req.headers['x-device-key'] || req.query.key;
    if (deviceKey === ADMIN_DEVICE_KEY) return next();
    if (password && adminPasswordHash && await bcrypt.compare(password, adminPasswordHash)) return next();
    return res.status(401).json({ error: 'Unauthorized' });
}

// ==================== AUTH ROUTES ====================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login-form' }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, name: req.user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`/auth-success?token=${token}&name=${encodeURIComponent(req.user.name)}&email=${req.user.email}&avatar=${req.user.avatar||''}`);
});
app.get('/auth-success', (req, res) => res.sendFile(path.join(__dirname, 'public', 'auth-success.html')));

app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Invalid data' });
    const users = getUsers();
    if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email exists' });
    const user = { id: uuidv4(), name, email, password: await bcrypt.hash(password, 12), provider: 'email', createdAt: new Date().toISOString(), lastLogin: new Date().toISOString() };
    users.push(user); saveUsers(users);
    logActivity(user.id, 'signup', 'Email signup');
    const token = jwt.sign({ id: user.id, email, name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name, email } });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = getUsers().find(u => u.email === email);
    if (!user?.password || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    user.lastLogin = new Date().toISOString(); saveUsers(getUsers());
    logActivity(user.id, 'login', 'Email login');
    const token = jwt.sign({ id: user.id, email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/api/logout', authRequired, (req, res) => {
    logActivity(req.user.id, 'logout', 'User logged out');
    req.logout(() => {});
    res.json({ success: true, message: 'Logged out successfully' });
});

app.post('/api/verify-device', async (req, res) => {
    const { password } = req.body;
    if (password && adminPasswordHash && await bcrypt.compare(password, adminPasswordHash)) {
        return res.json({ success: true, deviceKey: ADMIN_DEVICE_KEY });
    }
    res.status(401).json({ error: 'Wrong password' });
});

app.get('/api/me', authRequired, (req, res) => {
    const user = getUsers().find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ id: user.id, name: user.name, email: user.email, avatar: user.avatar, provider: user.provider, createdAt: user.createdAt, lastLogin: user.lastLogin });
});

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const movies = getMovies();
    const users = getUsers();
    const totalViews = movies.reduce((sum, m) => sum + (m.views || 0), 0);
    res.json({
        totalUsers: users.length,
        totalMovies: movies.length,
        totalViews,
        recentUsers: users.slice(-5).reverse(),
        recentMovies: movies.slice(-5).reverse(),
        topMovies: movies.sort((a, b) => (b.views || 0) - (a.views || 0)).slice(0, 5)
    });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
    res.json(getUsers().map(u => ({ id: u.id, name: u.name, email: u.email, provider: u.provider, createdAt: u.createdAt, lastLogin: u.lastLogin })).reverse());
});

// ==================== MOVIE ROUTES ====================
app.get('/api/movies', authRequired, (req, res) => {
    let movies = getMovies().reverse();
    if (req.query.genre && req.query.genre !== 'all') movies = movies.filter(m => m.genre === req.query.genre);
    res.json(movies);
});

app.get('/api/movies/:id', authRequired, (req, res) => {
    const movie = getMovies().find(m => m.id === req.params.id);
    if (!movie) return res.status(404).json({ error: 'Not found' });
    movie.views = (movie.views || 0) + 1; saveMovies(getMovies());
    res.json(movie);
});

app.get('/api/search', authRequired, (req, res) => {
    const q = (req.query.q || '').toLowerCase().trim();
    if (!q) return res.json([]);
    res.json(getMovies().filter(m => m.title.toLowerCase().includes(q) || m.genre.toLowerCase().includes(q) || (m.cast||'').toLowerCase().includes(q) || (m.director||'').toLowerCase().includes(q)));
});

app.post('/api/movies', requireAdmin, upload.fields([{ name: 'video' }, { name: 'poster' }]), (req, res) => {
    const { title, description, genre, year, duration, director, cast, producer, imdbRating, youtubeLink } = req.body;
    const movie = {
        id: uuidv4(), title: title || 'Untitled', description: description || '', genre: genre || 'Other',
        year: year || new Date().getFullYear(), duration: duration || 'Unknown',
        director: director || '', cast: cast || '', producer: producer || '', imdbRating: imdbRating || 'N/A',
        videoUrl: req.files?.video?.[0] ? '/uploads/' + req.files.video[0].filename : null,
        posterUrl: req.files?.poster?.[0] ? '/posters/' + req.files.poster[0].filename : null,
        filename: req.files?.video?.[0]?.originalname || null, youtubeLink: youtubeLink || null, views: 0, uploadDate: new Date().toISOString()
    };
    const movies = getMovies(); movies.push(movie); saveMovies(movies);
    logActivity('admin', 'upload', movie.title);
    res.json({ success: true, movie });
});

app.delete('/api/movies/:id', requireAdmin, (req, res) => {
    const movies = getMovies();
    const i = movies.findIndex(m => m.id === req.params.id);
    if (i === -1) return res.status(404).json({ error: 'Not found' });
    const m = movies[i];
    try { if (m.videoUrl) fs.unlinkSync(path.join(__dirname, m.videoUrl)); } catch(e) {}
    try { if (m.posterUrl) fs.unlinkSync(path.join(__dirname, m.posterUrl)); } catch(e) {}
    movies.splice(i, 1); saveMovies(movies);
    logActivity('admin', 'delete', m.title);
    res.json({ success: true });
});

app.get('/api/stream/:id', authRequired, (req, res) => {
    const movie = getMovies().find(m => m.id === req.params.id);
    if (!movie) return res.status(404).end();
    if (movie.youtubeLink) {
        let url = movie.youtubeLink;
        if (url.includes('youtu.be/')) url = `https://www.youtube.com/embed/${url.split('youtu.be/')[1]?.split('?')[0]}`;
        else if (url.includes('watch?v=')) url = `https://www.youtube.com/embed/${url.split('watch?v=')[1]?.split('&')[0]}`;
        return res.redirect(url);
    }
    if (movie.videoUrl) {
        const vp = path.join(__dirname, movie.videoUrl);
        if (!fs.existsSync(vp)) return res.status(404).end();
        const stat = fs.statSync(vp);
        const range = req.headers.range;
        if (range) {
            const [start, end] = range.replace(/bytes=/, '').split('-').map(Number);
            const e = end || stat.size - 1;
            res.writeHead(206, { 'Content-Range': `bytes ${start}-${e}/${stat.size}`, 'Accept-Ranges': 'bytes', 'Content-Length': e - start + 1, 'Content-Type': 'video/mp4' });
            fs.createReadStream(vp, { start, end: e }).pipe(res);
        } else {
            res.writeHead(200, { 'Content-Length': stat.size, 'Content-Type': 'video/mp4' });
            fs.createReadStream(vp).pipe(res);
        }
        return;
    }
    res.status(404).end();
});

// ==================== PAGES ====================
app.get('/admin', (req, res) => {
    const key = req.query.key;
    if (key === ADMIN_DEVICE_KEY) return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
    res.send(`<!DOCTYPE html><html><head><title>Admin - ONflix</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>
        *{margin:0;padding:0;box-sizing:border-box}body{background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;font-family:Arial}
        .box{text-align:center;background:#1a1a2e;padding:40px;border-radius:15px;border:2px solid #e50914;max-width:400px;width:90%}
        h1{color:#e50914;margin-bottom:20px}input{padding:15px;font-size:18px;border-radius:8px;border:1px solid #e50914;background:#111;color:#fff;text-align:center;width:100%;margin:10px 0}
        button{background:#e50914;color:#fff;padding:15px 35px;border:none;border-radius:8px;font-size:18px;cursor:pointer;font-weight:700;margin-top:10px}
        button:hover{background:#ff0f1f}#err{color:#e74c3c;margin-top:10px;display:none}</style></head><body>
        <div class="box"><h1>🔐 Admin Login</h1><p style="color:#aaa;margin-bottom:15px;">Enter password to access</p>
        <input type="password" id="pw" placeholder="Password"><br><button onclick="verify()">Unlock</button>
        <p id="err">❌ Wrong password!</p></div>
        <script>async function verify(){const p=document.getElementById('pw').value;try{const r=await fetch('/api/verify-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});const d=await r.json();if(d.success){localStorage.setItem('admin_device_key',d.deviceKey);location.href='/admin?key='+d.deviceKey}else{document.getElementById('err').style.display='block'}}catch(e){}}</script></body></html>`);
});

// Public routes (no login required)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/login-form', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login-form.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/help', (req, res) => res.sendFile(path.join(__dirname, 'public', 'help.html')));
app.get('/contact', (req, res) => res.sendFile(path.join(__dirname, 'public', 'contact.html')));

// Protected routes (login required)
app.get('/browse', authRequired, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/profile', authRequired, (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/myprofile', authRequired, (req, res) => res.sendFile(path.join(__dirname, 'public', 'myprofile.html')));
app.get('/watch/:id', authRequired, (req, res) => res.sendFile(path.join(__dirname, 'public', 'player.html')));

app.listen(PORT, () => console.log(`\n🎬 ONflix PRO: http://localhost:${PORT}\n👥 Users: ${getUsers().length}\n🎬 Movies: ${getMovies().length}\n`));