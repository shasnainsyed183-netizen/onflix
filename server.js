const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/posters', express.static('posters'));

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('posters')) fs.mkdirSync('posters');

const DB = 'movies.json';
if (!fs.existsSync(DB)) fs.writeFileSync(DB, '[]');

const getMovies = () => JSON.parse(fs.readFileSync(DB));
const saveMovies = (m) => fs.writeFileSync(DB, JSON.stringify(m, null, 2));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'poster') cb(null, 'posters/');
        else cb(null, 'uploads/');
    },
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 * 1024 } });

app.get('/api/movies', (req, res) => res.json(getMovies().reverse()));

app.get('/api/movies/:id', (req, res) => {
    const movies = getMovies();
    const movie = movies.find(m => m.id === req.params.id);
    if (!movie) return res.status(404).json({ error: 'Not found' });
    movie.views = (movie.views || 0) + 1;
    saveMovies(movies);
    res.json(movie);
});

app.post('/api/movies', upload.fields([{ name: 'video' }, { name: 'poster' }]), (req, res) => {
    if (!req.files || !req.files.video) return res.status(400).json({ error: 'Video required' });
    const { title, description, genre, year, duration, director, cast } = req.body;
    const movies = getMovies();
    const movie = {
        id: uuidv4(),
        title: title || 'Untitled',
        description: description || '',
        genre: genre || 'Other',
        year: year || '2024',
        duration: duration || 'Unknown',
        director: director || '',
        cast: cast || '',
        videoUrl: '/uploads/' + req.files.video[0].filename,
        posterUrl: req.files.poster ? '/posters/' + req.files.poster[0].filename : null,
        filename: req.files.video[0].originalname,
        views: 0,
        uploadDate: new Date().toISOString()
    };
    movies.push(movie);
    saveMovies(movies);
    res.json({ success: true, message: 'Uploaded!', movie });
});

app.delete('/api/movies/:id', (req, res) => {
    const movies = getMovies();
    const i = movies.findIndex(m => m.id === req.params.id);
    if (i === -1) return res.status(404).json({ error: 'Not found' });
    const m = movies[i];
    try { if (m.videoUrl) fs.unlinkSync(path.join(__dirname, m.videoUrl)); } catch(e) {}
    try { if (m.posterUrl) fs.unlinkSync(path.join(__dirname, m.posterUrl)); } catch(e) {}
    movies.splice(i, 1);
    saveMovies(movies);
    res.json({ success: true });
});

app.get('/api/search', (req, res) => {
    const q = (req.query.q || '').toLowerCase();
    res.json(getMovies().filter(m => m.title.toLowerCase().includes(q) || m.genre.toLowerCase().includes(q)));
});

app.get('/api/stream/:id', (req, res) => {
    const movie = getMovies().find(m => m.id === req.params.id);
    if (!movie) return res.status(404).end();
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
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/watch/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'player.html')));

app.listen(PORT, () => {
    console.log(`\n🎬 ONflix: http://localhost:${PORT}`);
    console.log(`📤 Upload: http://localhost:${PORT}/admin\n`);
});