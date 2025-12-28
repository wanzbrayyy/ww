
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
// Fungsi ini meneruskan permintaan dan menangani format respons
const proxyToWorkingApi = (endpoint, params = {}) => async (req, res) => {
    // Ganti placeholder di endpoint dengan params dari request
    let finalEndpoint = endpoint;
    for (const key in req.params) {
        finalEndpoint = finalEndpoint.replace(`:${key}`, req.params[key]);
    }

    const fullUrl = `${WORKING_API_BASE_URL}${finalEndpoint}`;
    console.log(`Proxying request to: ${fullUrl} with query:`, req.query);
    try {
        const response = await axios.get(fullUrl, { params: req.query });
        // API Railway Anda memiliki format {status, data}, kita hanya butuh 'data' nya untuk kompatibilitas.
        if (response.data && response.data.status === 'success') {
            res.json(response.data.data);
        } else {
             // Jika tidak ada 'status' atau bukan 'success', kirim apa adanya
            res.json(response.data);
        }
    } catch (error) {
        const status = error.response?.status || 500;
        const data = error.response?.data || { message: 'Failed to proxy request' };
        console.error(`Proxy error for ${fullUrl}:`, status, data);
        res.status(status).json(data);
    }
};


// --- ENDPOINT YANG DITERIMA VPS (SESUAI KEBUTUHAN ANDROID/FLUTTER) ---
// Rute-rute ini akan "diterjemahkan" ke rute API Railway
app.get('/api/movies/homepage', proxyToWorkingApi('/api/homepage'));

// Aplikasi minta /api/detail/:id, VPS akan meneruskannya ke /api/info/:id di Railway
app.get('/api/detail/:id', proxyToWorkingApi('/api/info/:id'));

// Aplikasi minta /api/sources/:id, VPS akan meneruskannya ke /api/sources/:id di Railway
app.get('/api/sources/:id', proxyToWorkingApi('/api/sources/:id'));


// --- RUTE OTENTIKASI & PROFIL (DIJALANKAN DI VPS) ---
const generateToken = (id) => jwt.sign({ id }, JWT_SECRET_AUTH, { expiresIn: '30d' });

app.post('/api/auth/register', async (req, res) => {
    const { fullName, username, email, password } = req.body;
    try {
        if (!fullName || !username || !email || !password) return res.status(400).json({ message: 'Please fill all fields' });
        const userExists = await User.findOne({ $or: [{email}, {username}] });
        if (userExists) return res.status(400).json({ message: 'User with this email or username already exists' });
        const user = await User.create({ fullName, username, email, password });
        res.status(201).json({ _id: user._id, token: generateToken(user._id) });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) return res.status(400).json({ message: 'Please provide email and password' });
        const user = await User.findOne({ email });
        if (user && (await user.matchPassword(password))) {
            res.json({ _id: user._id, fullName: user.fullName, email: user.email, token: generateToken(user._id) });
        } else {
            res.status(401).json({ message: 'Invalid email or password' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});

app.get('/api/users/profile', protect, async (req, res) => {
    try {
        res.json({
            _id: req.user._id, fullName: req.user.fullName, username: req.user.username,
            email: req.user.email, referralCode: req.user.referralCode
        });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});

app.put('/api/users/profile', protect, async (req, res) => {
    try {
        const user = req.user;
        user.username = req.body.username || user.username;
        user.email = req.body.email || user.email;
        if (req.body.password) user.password = req.body.password;
        const updatedUser = await user.save();
        res.json({
            _id: updatedUser._id, fullName: updatedUser.fullName, username: updatedUser.username,
            email: updatedUser.email, referralCode: updatedUser.referralCode
        });
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`MCUID PROXY Server running on http://0.0.0.0:${PORT}`);
    console.log(`Forwarding movie requests to: ${WORKING_API_BASE_URL}`);
});
