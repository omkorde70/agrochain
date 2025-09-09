// server.js - AgroChain backend (single-file)
// Save this to agrochain/backend/server.js

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();

// CONFIG from .env (with defaults)
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/agrochain';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123';
const PORT = process.env.PORT || 5000;
const FRONTEND_ORIGINS = (process.env.CORS_ORIGIN || 'http://127.0.0.1:5500,http://localhost:5500').split(',');

// Basic Middleware
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }));

// CORS allowing frontend origins and credentials (cookies)
app.use(cors({
  origin: (origin, callback) => {
    // allow requests with no origin (like curl/postman)
    if (!origin) return callback(null, true);
    if (FRONTEND_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('CORS not allowed'), false);
  },
  credentials: true
}));

// Ensure upload dir exists
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Multer setup (file uploads)
const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 12 * 1024 * 1024 } // 12 MB
});

// ====== Mongoose models ======
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=> console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('Mongo connection error:', err.message);
    process.exit(1);
  });

const userSchema = new mongoose.Schema({
  walletId: { type: String, required: true, unique: true },
  name: String,
  password: { type: String, required: true },
  role: { type: String, enum: ['farmer','buyer','logistics','consumer'], required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const txSchema = new mongoose.Schema({
  productId: { type: String, required: true },
  type: String,
  filePath: String,
  fileHash: String,
  meta: Object,
  actorRole: String,
  actorWallet: String,
  timestamp: { type: Date, default: Date.now },
  previousHash: String
});
const Transaction = mongoose.model('Transaction', txSchema);

// ====== Helpers ======
function signToken(user) {
  return jwt.sign({ id: user._id, role: user.role, walletId: user.walletId }, JWT_SECRET, { expiresIn: '4h' });
}

function authMiddleware(req, res, next) {
  try {
    const token = req.cookies && req.cookies.token;
    if (!token) return res.status(401).json({ message: 'Not authenticated' });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, role, walletId }
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ====== Routes ======

// Health
app.get('/api', (req, res) => res.json({ ok: true, time: new Date() }));

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { walletId, name, password, role } = req.body;
    if (!walletId || !password || !role) return res.status(400).json({ message: 'Missing fields' });

    const existing = await User.findOne({ walletId });
    if (existing) return res.status(400).json({ message: 'WalletId already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ walletId, name, password: hashed, role });
    await user.save();
    return res.json({ message: 'Signup successful' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { walletId, password } = req.body;
    if (!walletId || !password) return res.status(400).json({ message: 'Missing credentials' });

    const user = await User.findOne({ walletId });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Invalid credentials' });

    const token = signToken(user);
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('token', token, { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax', maxAge: 4 * 3600 * 1000 });
    return res.json({ message: 'Login successful', role: user.role, walletId: user.walletId, name: user.name });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

// Dashboard (protected)
app.get('/api/dashboard', authMiddleware, (req, res) => {
  const role = req.user.role;
  const features = {
    farmer: ['Smart Crop Listing','Direct Sales Hub','AI Market Intelligence','Supply Chain Tracking'],
    buyer: ['Smart Product Search','Quality Verification','Bulk Procurement','Smart Payment System'],
    logistics: ['Fleet Management','Cold Chain Monitoring','Delivery Optimization','Inventory Tracking'],
    consumer: ['Product Traceability','Quality Reports','Subscription Box','Sustainability Score']
  };
  res.json({ role, features: features[role] || [] });
});

// Upload transaction (protected)
app.post('/api/transactions', authMiddleware, upload.single('document'), async (req, res) => {
  try {
    const { productId, type, meta } = req.body;
    if (!productId || !type) return res.status(400).json({ message: 'productId and type required' });
    if (!req.file) return res.status(400).json({ message: 'Document required' });

    const fileBuffer = fs.readFileSync(req.file.path);
    const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // find previous hash for the product
    const prev = await Transaction.findOne({ productId }).sort({ timestamp: -1 });

    const tx = new Transaction({
      productId,
      type,
      filePath: path.relative(path.join(__dirname), req.file.path).replace(/\\/g,'/'),
      fileHash,
      meta: meta ? JSON.parse(meta) : {},
      actorRole: req.user.role,
      actorWallet: req.user.walletId,
      previousHash: prev ? prev.fileHash : null
    });

    await tx.save();
    return res.json({
      message: 'Transaction recorded',
      tx: {
        id: tx._id,
        productId: tx.productId,
        fileHash: tx.fileHash,
        previousHash: tx.previousHash,
        timestamp: tx.timestamp,
        filePath: tx.filePath
      }
    });

  } catch (err) {
    console.error('transactions error', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// List transactions (protected)
app.get('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const { productId, actorWallet } = req.query;
    const filter = {};
    if (productId) filter.productId = productId;
    if (actorWallet) filter.actorWallet = actorWallet;
    const txs = await Transaction.find(filter).sort({ timestamp: -1 }).limit(200);
    return res.json({ count: txs.length, txs });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Serve uploaded files (development only)
app.use('/uploads', express.static(UPLOAD_DIR));

// Start server
app.listen(PORT, () => console.log(`🚀 Backend running on http://localhost:${PORT}`));
