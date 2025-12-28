const express = require('express');
const axios = require('axios');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const WORKING_API_BASE_URL = "https://mov-production-a578.up.railway.app"; 
const JWT_SECRET_AUTH = "KUNCI_RAHASIA_ANDA_YANG_SANGAT_AMAN_DAN_PANJANG";
const MONGO_URI = "mongodb+srv://maverickuniverse405:1m8MIgmKfK2QwBNe@cluster0.il8d4jx.mongodb.net/digi?appName=Cluster0";

app.use(express.json());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log(err));

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

userSchema.methods.matchPassword = async function(p) { 
    return await bcrypt.compare(p, this.password); 
};

const User = mongoose.model('User', userSchema);

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

const proxyToWorkingApi = (endpoint) => async (req, res) => {
    const fullUrl = `${WORKING_API_BASE_URL}${endpoint}`;
    try {
        const response = await axios.get(fullUrl, { 
            params: req.query,
            timeout: 15000 
        });

        if (response.data && response.data.status === 'success') {
            res.json(response.data);
        } else {
            res.json(response.data);
        }
    } catch (error) {
        const status = error.response?.status || 500;
        const message = error.response?.data?.message || error.message || 'Failed to proxy request';
        res.status(status).json({ status: 'error', message });
    }
};

app.get('/api/homepage', proxyToWorkingApi('/api/homepage'));

app.get('/api/trending', proxyToWorkingApi('/api/trending'));

app.get('/api/search/:query', (req, res) => {
    const query = encodeURIComponent(req.params.query);
    return proxyToWorkingApi(`/api/search/${query}`)(req, res);
});

app.get('/api/info/:id', (req, res) => {
    return proxyToWorkingApi(`/api/info/${req.params.id}`)(req, res);
});

app.get('/api/detail/:id', (req, res) => {
    return proxyToWorkingApi(`/api/info/${req.params.id}`)(req, res);
});

app.get('/api/sources/:id', (req, res) => {
    return proxyToWorkingApi(`/api/sources/${req.params.id}`)(req, res);
});

app.get('/api/download', async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).send("Missing url parameter");
    const railwayDownloadUrl = `${WORKING_API_BASE_URL}/api/download?url=${encodeURIComponent(targetUrl)}`;
    res.redirect(railwayDownloadUrl);
});

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

app.get('/', (req, res) => {
    res.send('Server is running properly.');
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});
