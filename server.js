const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const uuidv4 = () => crypto.randomUUID();
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'onflix_super_secret_key_2025';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/posters', express.static('posters'));

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

// ==================== AUTH MIDDLEWARE ====================
function authRequired(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Please login first' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch(e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
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
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
    
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email } });
});

app.get('/api/me', authRequired, (req, res) => {
    const users = getUsers();
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ id: user.id, name: user.name, email: user.email });
});

app.post('/api/verify-device', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) res.json({ success: true, deviceKey: ADMIN_DEVICE_KEY });
    else res.status(401).json({ error: 'Wrong password' });
});
// =======================================================

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'poster') cb(null, 'posters/');
        else cb(null, 'uploads/');
    },
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});

const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 * 1024 } });

// Public routes (PROTECTED - login required for watching)
app.get('/api/movies', authRequired, (req, res) => res.json(getMovies().reverse()));

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
        m.title.toLowerCase().includes(q) ||
        m.genre.toLowerCase().includes(q) ||
        (m.description && m.description.toLowerCase().includes(q)) ||
        (m.director && m.director.toLowerCase().includes(q)) ||
        (m.cast && m.cast.toLowerCase().includes(q))
    );
    res.json(movies);
});

// Admin routes
app.post('/api/movies', requireAdmin, upload.fields([{ name: 'video' }, { name: 'poster' }]), (req, res) => {
    if ((!req.files || !req.files.video) && !req.body.youtubeLink) {
        return res.status(400).json({ error: 'Video file ya YouTube link dono mein se ek zaroori hai' });
    }
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
        videoUrl: req.files && req.files.video ? '/uploads/' + req.files.video[0].filename : null,
        posterUrl: req.files && req.files.poster ? '/posters/' + req.files.poster[0].filename : null,
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
    const m = movies[i];
    try { if (m.videoUrl) fs.unlinkSync(path.join(__dirname, m.videoUrl)); } catch(e) {}
    try { if (m.posterUrl) fs.unlinkSync(path.join(__dirname, m.posterUrl)); } catch(e) {}
    movies.splice(i, 1);
    saveMovies(movies);
    res.json({ success: true, message: 'Movie deleted!' });
});

app.get('/api/stream/:id', authRequired, (req, res) => {
    const movie = getMovies().find(m => m.id === req.params.id);
    if (!movie) return res.status(404).end();
    if (movie.youtubeLink) return res.redirect(movie.youtubeLink);
    const vp = path.join(__dirname, movie.videoUrl);
    if (!fs.existsSync(vp)) return res.status(404).end();
    const stat = fs.statSync(vp);
    const range = req.headers.range;
    if (range) {
        const [start, end] = range.replace(/bytes=/, '').split('-').map(Number);
        const e = end || stat.size - 1;
        res.writeHead(206, {
            'Content-Range': `bytes ${start}-${e}/${stat.size}`,
            'Accept-Ranges': 'bytes',
            'Content-Length': e - start + 1,
            'Content-Type': 'video/mp4'
        });
        fs.createReadStream(vp, { start, end: e }).pipe(res);
    } else {
        res.writeHead(200, { 'Content-Length': stat.size, 'Content-Type': 'video/mp4' });
        fs.createReadStream(vp).pipe(res);
    }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/watch/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'player.html')));

app.listen(PORT, () => {
    console.log(`\n🎬 ONflix Auth Ready! http://localhost:${PORT}\n`);
});