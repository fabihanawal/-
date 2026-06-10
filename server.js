const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB সংযোগ
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/swasthya-seba';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB সংযুক্ত হয়েছে'))
.catch(err => console.log('❌ MongoDB সংযোগ ব্যর্থ:', err));

// ========== স্কিমা এবং মডেল ==========

// ব্যবহারকারী মডেল
const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    phone: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('User', UserSchema);

// অর্ডার মডেল
const OrderSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    items: [{
        medicineId: Number,
        name: String,
        price: Number,
        quantity: Number
    }],
    totalAmount: {
        type: Number,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'shipped', 'delivered'],
        default: 'pending'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Order = mongoose.model('Order', OrderSchema);

// JWT সিক্রেট
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ========== রুট ==========

// 1. রেজিস্ট্রেশন
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, phone, password, confirmPassword } = req.body;

        // ভ্যালিডেশন
        if (!name || !email || !phone || !password) {
            return res.status(400).json({ success: false, message: 'সব ফিল্ড প্রয়োজন' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ success: false, message: 'পাসওয়ার্ড মিলছে না' });
        }

        // ইমেইল চেক করুন
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'এই ইমেইল ইতিমধ্যে বিদ্যমান' });
        }

        // পাসওয়ার্ড এনক্রিপ্ট করুন
        const hashedPassword = await bcrypt.hash(password, 10);

        // নতুন ব্যবহারকারী তৈরি করুন
        const newUser = new User({
            name,
            email,
            phone,
            password: hashedPassword
        });

        await newUser.save();

        // JWT টোকেন তৈরি করুন
        const token = jwt.sign({ userId: newUser._id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            success: true,
            message: 'রেজিস্ট্রেশন সফল',
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email
            },
            token
        });

    } catch (error) {
        console.error('রেজিস্ট্রেশন ত্রুটি:', error);
        res.status(500).json({ success: false, message: 'সার্ভার ত্রুটি' });
    }
});

// 2. লগইন
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // ভ্যালিডেশন
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'ইমেইল এবং পাসওয়ার্ড প্রয়োজন' });
        }

        // ব্যবহারকারী খুঁজুন
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, message: 'ইনভ্যালিড ইমেইল বা পাসওয়ার্ড' });
        }

        // পাসওয়ার্ড যাচাই করুন
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'ইনভ্যালিড ইমেইল বা পাসওয়ার্ড' });
        }

        // JWT টোকেন তৈরি করুন
        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            success: true,
            message: 'লগইন সফল',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            token
        });

    } catch (error) {
        console.error('লগইন ত্রুটি:', error);
        res.status(500).json({ success: false, message: 'সার্ভার ত্রুটি' });
    }
});

// 3. অর্ডার তৈরি করুন
app.post('/api/orders/create', async (req, res) => {
    try {
        const { userId, items, totalAmount, token } = req.body;

        // টোকেন যাচাই করুন
        if (!token) {
            return res.status(401).json({ success: false, message: 'অথেন্টিকেশন প্রয়োজন' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.userId !== userId) {
            return res.status(403).json({ success: false, message: 'অনুমতি নেই' });
        }

        // ব্যবহারকারী বিদ্যমান চেক করুন
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'ব্যবহারকারী খুঁজে পাওয়া যায়নি' });
        }

        // নতুন অর্ডার তৈরি করুন
        const newOrder = new Order({
            userId,
            items,
            totalAmount,
            status: 'pending'
        });

        await newOrder.save();

        res.status(201).json({
            success: true,
            message: 'অর্ডার সফলভাবে তৈরি হয়েছে',
            order: {
                id: newOrder._id,
                totalAmount: newOrder.totalAmount,
                status: newOrder.status,
                createdAt: newOrder.createdAt
            }
        });

    } catch (error) {
        console.error('অর্ডার তৈরি ত্রুটি:', error);
        res.status(500).json({ success: false, message: 'সার্ভার ত্রুটি' });
    }
});

// 4. ব্যবহারকারীর অর্ডার পান
app.get('/api/orders/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { token } = req.headers;

        // টোকেন যাচাই করুন
        if (!token) {
            return res.status(401).json({ success: false, message: 'অথেন্টিকেশন প্রয়োজন' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.userId !== userId) {
            return res.status(403).json({ success: false, message: 'অনুমতি নেই' });
        }

        const orders = await Order.find({ userId });

        res.json({
            success: true,
            orders
        });

    } catch (error) {
        console.error('অর্ডার পান ত্রুটি:', error);
        res.status(500).json({ success: false, message: 'সার্ভার ত্রুটি' });
    }
});

// 5. স্বাস্থ্যতা চেক
app.get('/api/health', (req, res) => {
    res.json({ success: true, message: 'সার্ভার চলছে' });
});

// সার্ভার শুরু করুন
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ সার্ভার ${PORT} পোর্টে চলছে`);
});
