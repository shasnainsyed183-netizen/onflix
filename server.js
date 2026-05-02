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
const JWT_SECRET = process.env.JWT_SECRET || 'onflix_super_secret_key_2025';

// ==================== GOOGLE CREDENTIALS ====================
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://onflix-production.up.railway.app';

// ==================== CLOUDINARY CONFIG ====================
cloudinary.config({
    cloud_name: 'dia6yxhsj',
    api_key: '796297943479477',
    api_secret: 'wVOK1o49EYc7YV4ee6kzvFxpTIc'
});
// ==========================================================

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/posters', express.static('posters'));
app.use(session({ secret: 'onflix_session', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('posters')) fs.mkdirSync('posters');

const DB = 'movies.json';
const USERS_DB = 'users.json';

if (!fs.existsSync(DB)) fs.writeFileSync(DB, '[]');
if (!fs.existsSync(USERS_DB)) fs.writeFileSync(USERS_DB, '[]');

const getMovies = () => JSON.parse(fs.readFileSync(DB));
const saveMovies = (m) => fs.writeFileSync(DB, JSON.stringify(m, null, 2));
const getUsers = () => JSON.parse(fs.readFileSync(USERS_DB));
const saveUsers = (u) => fs.writeFileSync(USERS_DB, JSON.stringify(u, null, 2));

// ==================== PASSPORT GOOGLE ====================
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL + '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    const users = getUsers();
    let user = users.find(u => u.email === profile.emails[0].value);
    if (!user) {
        user = { id: uuidv4(), name: profile.displayName, email: profile.emails[0].value, googleId: profile.id, createdAt: new Date().toISOString() };
        users.push(user);
        saveUsers(users);
    }
    return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const users = getUsers();
    const user = users.find(u => u.id === id);
    done(null, user);
});
// =========================================================

// ==================== AUTH MIDDLEWARE ====================
function authRequired(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (req.isAuthenticated && req.isAuthenticated()) return next();
    if (token) {
        try { req.user = jwt.verify(token, JWT_SECRET); return next(); } catch(e) {}
    }
    return res.status(401).json({ error: 'Please login first' });
}

const ADMIN_PASSWORD = 'Shash@123';
const ADMIN_DEVICE_KEY = 'onflix_admin_device_verified';

function requireAdmin(req, res, next) {
    const password = req.headers['x-admin-password'] || req.query.password;
    const deviceKey = req.headers['x-device-key'];
    if (password === ADMIN_PASSWORD || deviceKey === ADMIN_DEVICE_KEY) return next();
    return res.status(401).json({ error: 'Unauthorized' });
}
// =========================================================

// ==================== GOOGLE AUTH ROUTES ====================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, name: req.user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`/auth-success?token=${token}&name=${req.user.name}&email=${req.user.email}`);
});
app.get('/auth-success', (req, res) => res.sendFile(path.join(__dirname, 'public', 'auth-success.html')));
// ==========================================================

// ==================== AUTH ROUTES ====================
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    const users = getUsers();
    if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { id: uuidv4(), name, email, password: hashedPassword, createdAt: new Date().toISOString() };
    users.push(user);
    saveUsers(users);
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'All fields required' });
    const users = getUsers();
    const user = users.find(u => u.email === email);
    if (!user || !user.password) return res.status(401).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email } });
});

app.get('/api/me', authRequired, (req, res) => res.json(req.user));
app.post('/api/verify-device', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) res.json({ success: true, deviceKey: ADMIN_DEVICE_KEY });
    else res.status(401).json({ error: 'Wrong password' });
});
// ==========================================================

// ==================== CLOUDINARY STORAGE ====================
const videoStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'onflix_videos',
        resource_type: 'video',
        format: async (req, file) => 'mp4',
    }
});

const posterStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'onflix_posters',
        format: async (req, file) => 'jpg',
    }
});

const uploadVideo = multer({ storage: videoStorage, limits: { fileSize: 500 * 1024 * 1024 } });
const uploadPoster = multer({ storage: posterStorage });
// ==========================================================

// ==================== MOVIE ROUTES ====================
app.get('/api/movies', authRequired, (req, res) => {
    let movies = getMovies().reverse();
    const genre = req.query.genre;
    if (genre && genre !== 'all') movies = movies.filter(m => m.genre === genre);
    res.json(movies);
});

app.get('/api/movies/:id', authRequired, (req, res) => {
    const movies = getMovies();
    const movie = movies.find(m => m.id === req.params.id);
    if (!movie) return res.status(404).json({ error: 'Not found' });
    movie.views = (movie.views || 0) + 1;
    saveMovies(movies);
    res.json(movie);
});

app.get('/api/search', authRequired, (req, res) => {
    const q = (req.query.q || '').toLowerCase().trim();
    if (!q) return res.json(getMovies().reverse());
    const movies = getMovies().filter(m => 
        m.title.toLowerCase().includes(q) || m.genre.toLowerCase().includes(q) ||
        (m.description && m.description.toLowerCase().includes(q)) ||
        (m.director && m.director.toLowerCase().includes(q)) ||
        (m.cast && m.cast.toLowerCase().includes(q))
    );
    res.json(movies);
});

app.post('/api/movies', requireAdmin, uploadVideo.fields([{ name: 'video' }, { name: 'poster' }]), (req, res) => {
    const { title, description, genre, year, duration, director, cast, youtubeLink } = req.body;
    const movies = getMovies();
    const movie = {
        id: uuidv4(),
        title: title || 'Untitled',
        description: description || 'No description',
        genre: genre || 'Other',
        year: year || new Date().getFullYear(),
        duration: duration || 'Unknown',
        director: director || 'Unknown',
        cast: cast || 'Unknown',
        videoUrl: req.files && req.files.video ? req.files.video[0].path : null,
        posterUrl: req.files && req.files.poster ? req.files.poster[0].path : null,
        filename: req.files && req.files.video ? req.files.video[0].originalname : null,
        youtubeLink: youtubeLink || null,
        views: 0,
        uploadDate: new Date().toISOString()
    };
    movies.push(movie);
    saveMovies(movies);
    res.json({ success: true, message: 'Movie uploaded! 🎉', movie });
});

app.delete('/api/movies/:id', requireAdmin, (req, res) => {
    const movies = getMovies();
    const i = movies.findIndex(m => m.id === req.params.id);
    if (i === -1) return res.status(404).json({ error: 'Not found' });
    movies.splice(i, 1);
    saveMovies(movies);
    res.json({ success: true });
});

app.get('/api/stream/:id', authRequired, (req, res) => {
    const movie = getMovies().find(m => m.id === req.params.id);
    if (!movie) return res.status(404).end();
    if (movie.youtubeLink) return res.redirect(movie.youtubeLink);
    if (movie.videoUrl && movie.videoUrl.includes('cloudinary')) return res.redirect(movie.videoUrl);
    res.status(404).json({ error: 'Video not available' });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/watch/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'player.html')));

app.listen(PORT, () => console.log(`\n🎬 ONflix Cloud: http://localhost:${PORT}\n`));