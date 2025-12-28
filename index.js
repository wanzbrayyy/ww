
const express = require('express');
const axios = require('axios');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Ganti URL ini dengan URL API Railway Anda yang sudah berhasil
const WORKING_API_BASE_URL = "https://mov-production-a578.up.railway.app/";
const JWT_SECRET_AUTH = "KUNCI_RAHASIA_ANDA_YANG_SANGAT_AMAN_DAN_PANJANG";

app.use(express.json());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    next();
});

// --- KONEKSI DATABASE & MODEL (UNTUK FITUR AUTH) ---
const MONGO_URI = "mongodb+srv://maverickuniverse405:1m8MIgmKfK2QwBNe@cluster0.il8d4jx.mongodb.net/digi?appName=Cluster0";
mongoose.connect(MONGO_URI).then(() => console.log('MongoDB Connected')).catch(err => console.log(err));

const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    referralCode: { type: String, unique: true, sparse: true }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    if (!this.referralCode) {
         this.referralCode = 'MCU-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    }
    next();
});
userSchema.methods.matchPassword = async function(p) { return await bcrypt.compare(p, this.password); };
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE OTENTIKASI ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET_AUTH);
            req.user = await User.findById(decoded.id).select('-password');
            if (!req.user) return res.status(401).json({ message: 'Not authorized, user not found' });
            next();
        } catch (error) {
            return res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }
    if (!token) {
        return res.status(401).json({ message: 'Not authorized, no token' });
    }
};

// --- PROXY CERDAS KE API RAILWAY ---
// Fungsi ini meneruskan permintaan dan membungkusnya dalam format {status, data}
const proxyToWorkingApi = (endpoint) => async (req, res) => {
    const fullUrl = `${WORKING_API_BASE_URL}${endpoint}`;
    console.log(`Proxying request for Flutter App to: ${fullUrl}`);
    try {
        const response = await axios.get(fullUrl, { params: req.query });
        // API Railway Anda sudah memiliki format {status, data}, jadi kita teruskan saja
        res.status(response.status).json(response.data);
    } catch (error) {
        const status = error.response?.status || 500;
        const data = error.response?.data || { status: 'error', message: 'Failed to proxy request' };
        console.error(`Proxy error for ${fullUrl}:`, status, data);
        res.status(status).json(data);
    }
};

// --- ENDPOINT YANG SESUAI DENGAN KEBUTUHAN FLUTTER ---
app.get('/api/homepage', proxyToWorkingApi('/api/homepage'));
app.get('/api/info/:id', (req, res) => proxyToWorkingApi(`/api/info/${req.params.id}`)(req, res));
app.get('/api/search/:query', (req, res) => proxyToWorkingApi(`/api/search/${req.params.query}`)(req, res));
app.get('/api/sources/:id', (req, res) => proxyToWorkingApi(`/api/sources/${req.params.id}`)(req, res));


// --- RUTE OTENTIKASI & PROFIL (DIJALANKAN DI VPS) ---
// (Disembunyikan untuk saat ini agar tidak bentrok, bisa ditambahkan nanti jika perlu)
/*
const generateToken = (id) => jwt.sign({ id }, JWT_SECRET_AUTH, { expiresIn: '30d' });
// ... (semua route auth di sini) ...
*/

app.listen(PORT, '0.0.0.0', () => {
    console.log(`MCUID PROXY Server (FLUTTER COMPATIBLE) running on http://0.0.0.0:${PORT}`);
    console.log(`Forwarding movie requests to: ${WORKING_API_BASE_URL}`);
});
