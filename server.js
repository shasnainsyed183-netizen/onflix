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
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const uuidv4 = () => crypto.randomUUID();
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'onflix_ultra_secure_jwt_secret_2025';
const RATE_LIMIT = {};

// ==================== CONFIG ====================
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://onflix-production.up.railway.app';
const ADMIN_DEVICE_KEY = process.env.ADMIN_DEVICE_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Shash@123';
let adminPasswordHash = null;

// ==================== CLOUDINARY ====================
cloudinary.config({
    cloud_name: process.env.CLOUD_NAME || 'dia6yxhsj',
    api_key: process.env.CLOUD_API_KEY || '796297943479477',
    api_secret: process.env.CLOUD_API_SECRET || 'wVOK1o49EYc7YV4ee6kzvFxpTIc'
});

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({ secret: JWT_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    const ip = req.ip;
    if (!RATE_LIMIT[ip]) RATE_LIMIT[ip] = { count: 0, reset: Date.now() + 60000 };
    if (Date.now() > RATE_LIMIT[ip].reset) RATE_LIMIT[ip] = { count: 0, reset: Date.now() + 60000 };
    RATE_LIMIT[ip].count++;
    if (RATE_LIMIT[ip].count > 200) return res.status(429).json({ error: 'Too many requests' });
    next();
});

const loginAttempts = {};
function checkBruteForce(ip) {
    if (!loginAttempts[ip]) loginAttempts[ip] = { count: 0, blocked: false, unblock: 0 };
    if (loginAttempts[ip].blocked && Date.now() < loginAttempts[ip].unblock) return true;
    if (loginAttempts[ip].blocked && Date.now() > loginAttempts[ip].unblock) loginAttempts[ip] = { count: 0, blocked: false, unblock: 0 };
    return false;
}
function recordFailedAttempt(ip) {
    if (!loginAttempts[ip]) loginAttempts[ip] = { count: 0, blocked: false, unblock: 0 };
    loginAttempts[ip].count++;
    if (loginAttempts[ip].count >= 5) {
        loginAttempts[ip].blocked = true;
        loginAttempts[ip].unblock = Date.now() + 900000;
    }
}

// ==================== DATABASE ====================
const DB = 'movies.json';
const USERS_DB = 'users.json';
if (!fs.existsSync(DB)) fs.writeFileSync(DB, '[]');
if (!fs.existsSync(USERS_DB)) fs.writeFileSync(USERS_DB, '[]');
const getMovies = () => JSON.parse(fs.readFileSync(DB));
const saveMovies = (m) => fs.writeFileSync(DB, JSON.stringify(m, null, 2));
const getUsers = () => JSON.parse(fs.readFileSync(USERS_DB));
const saveUsers = (u) => fs.writeFileSync(USERS_DB, JSON.stringify(u, null, 2));

// ==================== INIT ADMIN ====================
async function initAdmin() {
    if (!adminPasswordHash) {
        adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    }
}
initAdmin();

// ==================== PASSPORT ====================
passport.use(new GoogleStrategy({ clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET, callbackURL: CALLBACK_URL + '/auth/google/callback' },
    async (accessToken, refreshToken, profile, done) => {
        const users = getUsers();
        let user = users.find(u => u.email === profile.emails[0].value);
        if (!user) {
            user = { id: uuidv4(), name: profile.displayName, email: profile.emails[0].value, googleId: profile.id, createdAt: new Date().toISOString() };
            users.push(user); saveUsers(users);
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
    const ip = req.ip;
    
    if (checkBruteForce(ip)) return res.status(429).json({ error: 'Blocked for 15 minutes' });
    if (deviceKey === ADMIN_DEVICE_KEY) return next();
    if (password && adminPasswordHash && await bcrypt.compare(password, adminPasswordHash)) return next();
    
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Unauthorized' });
}

// ==================== STORAGE ====================
const videoStorage = new CloudinaryStorage({ cloudinary, params: { folder: 'onflix_videos', resource_type: 'video' } });
const posterStorage = new CloudinaryStorage({ cloudinary, params: { folder: 'onflix_posters' } });
const uploadVideo = multer({ storage: videoStorage, limits: { fileSize: 500 * 1024 * 1024 } });
const uploadPoster = multer({ storage: posterStorage });

// ==================== ROUTES ====================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, name: req.user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`/auth-success?token=${token}&name=${req.user.name}&email=${req.user.email}`);
});
app.get('/auth-success', (req, res) => res.sendFile(path.join(__dirname, 'public', 'auth-success.html')));

app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Invalid data' });
    const users = getUsers();
    if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email exists' });
    const user = { id: uuidv4(), name, email, password: await bcrypt.hash(password, 12), createdAt: new Date().toISOString() };
    users.push(user); saveUsers(users);
    const token = jwt.sign({ id: user.id, email, name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name, email } });
});

app.post('/api/login', async (req, res) => {
    const ip = req.ip;
    if (checkBruteForce(ip)) return res.status(429).json({ error: 'Blocked' });
    const { email, password } = req.body;
    const user = getUsers().find(u => u.email === email);
    if (!user?.password || !await bcrypt.compare(password, user.password)) {
        recordFailedAttempt(ip);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/api/verify-device', async (req, res) => {
    const { password } = req.body;
    if (password && adminPasswordHash && await bcrypt.compare(password, adminPasswordHash)) {
        return res.json({ success: true, deviceKey: ADMIN_DEVICE_KEY });
    }
    res.status(401).json({ error: 'Wrong password' });
});

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
    res.json(getMovies().filter(m => m.title.toLowerCase().includes(q) || m.genre.toLowerCase().includes(q)));
});

app.post('/api/movies', requireAdmin, uploadVideo.fields([{ name: 'video' }, { name: 'poster' }]), (req, res) => {
    const { title, description, genre, year, duration, director, cast, youtubeLink } = req.body;
    const movie = {
        id: uuidv4(), title: title || 'Untitled', description: description || '', genre: genre || 'Other',
        year: year || new Date().getFullYear(), duration: duration || 'Unknown', director: director || '', cast: cast || '',
        videoUrl: req.files?.video?.[0]?.path || null, posterUrl: req.files?.poster?.[0]?.path || null,
        filename: req.files?.video?.[0]?.originalname || null, youtubeLink: youtubeLink || null, views: 0, uploadDate: new Date().toISOString()
    };
    const movies = getMovies(); movies.push(movie); saveMovies(movies);
    res.json({ success: true, movie });
});

app.delete('/api/movies/:id', requireAdmin, (req, res) => {
    const movies = getMovies();
    const i = movies.findIndex(m => m.id === req.params.id);
    if (i === -1) return res.status(404).json({ error: 'Not found' });
    movies.splice(i, 1); saveMovies(movies);
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
    if (movie.videoUrl) return res.redirect(movie.videoUrl);
    res.status(404).end();
});

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

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/watch/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'player.html')));

app.listen(PORT, () => console.log(`\n🛡️ ONflix SECURE: http://localhost:${PORT}\n🔑 Admin: ${ADMIN_PASSWORD}\n`));