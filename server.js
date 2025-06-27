require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const emailValidator = require('email-validator');
const { GridFSBucket } = require('mongodb');

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || origin === 'http://localhost:5173') {
      return callback(null, true);
    }
    if (origin && origin.endsWith('.vercel.app')) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
  })
);

// Multer configuration for memory storage (for GridFS)
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Invalid file type. Only PDF, DOC, or DOCX allowed.'), false);
    }
    if (file.size > 2 * 1024 * 1024) {
      return cb(new Error('File size must be less than 2MB.'), false);
    }
    cb(null, true);
  },
});

// MongoDB connection and GridFS setup
let gfs;
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('MongoDB connected');
    gfs = new GridFSBucket(mongoose.connection.db, {
      bucketName: 'uploads',
    });

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Optional: shut down server if DB fails
  });


// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: String,
  address: String,
  cvFileId: { type: mongoose.Schema.Types.ObjectId, ref: 'uploads.files' }, // GridFS file ID
  verified: { type: Boolean, default: false },
  otp: String,
  otpExpires: Date,
});
const User = mongoose.model('User', userSchema);

// Validation helpers
const validateName = (name) => name && name.length >= 2;
const validateEmail = (email) => emailValidator.validate(email);
const validatePassword = (password) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password);
const validatePhone = (phone) => /^\d{10}$/.test(phone);
const validateAddress = (address) => address && address.length >= 5;

// Nodemailer transport
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Signup Route
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    if (!validateName(name)) throw new Error('Name must be at least 2 characters');
    if (!email) throw new Error('Email is required');
    if (!validateEmail(email)) throw new Error('Invalid email format');
    if (!password) throw new Error('Password is required');
    if (!validatePassword(password))
      throw new Error('Password must be 8+ characters with uppercase, lowercase, number, and special character');

    const existingUser = await User.findOne({ email });
    if (existingUser) throw new Error('User already exists');

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpires,
      verified: false,
    });
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for Email Verification',
      html: `<p>Your OTP is <b>${otp}</b>. It is valid for 10 minutes.</p>`,
    });

    res.status(201).json({ message: 'User registered. Please verify your email with the OTP sent.' });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(err.message.includes('User already exists') ? 400 : 500).json({ message: err.message || 'Server error' });
  }
});

// OTP Verification Route
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    if (!email) throw new Error('Email is required');
    if (!otp) throw new Error('OTP is required');

    const user = await User.findOne({ email });
    if (!user) throw new Error('User not found');
    if (user.verified) throw new Error('User already verified');
    if (user.otp !== otp) throw new Error('Invalid OTP');
    if (user.otpExpires < Date.now()) throw new Error('OTP expired');

    user.verified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully' });
  } catch (err) {
    console.error('OTP verification error:', err.message);
    res.status(400).json({ message: err.message || 'Invalid or expired OTP' });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email) return res.status(400).json({ message: 'Email is required' });
  if (!password) return res.status(400).json({ message: 'Password is required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (!user.verified) return res.status(400).json({ message: 'Email not verified' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, userId: user._id });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Auth Middleware
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Profile Update Route (store CV in GridFS)
app.post('/api/profile', authenticate, upload.single('cv'), async (req, res) => {
  const { name, phone, address } = req.body;
  const cv = req.file;

  if (!validateName(name)) return res.status(400).json({ message: 'Name must be at least 2 characters' });
  if (!validatePhone(phone)) return res.status(400).json({ message: 'Phone number must be 10 digits' });
  if (!validateAddress(address)) return res.status(400).json({ message: 'Address must be at least 5 characters' });
  if (!cv) return res.status(400).json({ message: 'CV is required' });

  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Delete old CV from GridFS
    if (user.cvFileId) {
      await gfs.delete(user.cvFileId);
    }

    // Upload new CV to GridFS
    const uploadStream = gfs.openUploadStream(cv.originalname, {
      contentType: cv.mimetype,
    });
    uploadStream.write(cv.buffer);
    uploadStream.end();

    const fileId = await new Promise((resolve, reject) => {
      uploadStream.on('finish', () => resolve(uploadStream.id));
      uploadStream.on('error', (err) => reject(err));
    });

    user.name = name;
    user.phone = phone;
    user.address = address;
    user.cvFileId = fileId;

    await user.save();
    res.json({ message: 'Profile updated successfully', fileId });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Serve CV files from GridFS
app.get('/api/cv/:fileId', async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.fileId);
    const file = await gfs.find({ _id: fileId }).toArray();

    if (!file || file.length === 0) {
      return res.status(404).json({ message: 'File not found' });
    }

    res.set('Content-Type', file[0].contentType);
    const downloadStream = gfs.openDownloadStream(fileId);
    downloadStream.pipe(res);

    downloadStream.on('error', (err) => {
      console.error('Download stream error:', err);
      res.status(500).json({ message: 'Error serving file' });
    });
  } catch (err) {
    console.error('Serve CV error:', err);
    res.status(400).json({ message: 'Invalid file ID' });
  }
});

// Resend OTP Route
app.post('/api/resend-otp', async (req, res) => {
  const { email } = req.body;

  try {
    if (!email) throw new Error('Email is required');
    const user = await User.findOne({ email });
    if (!user) throw new Error('User not found');
    if (user.verified) throw new Error('User already verified');

    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your New OTP for Email Verification',
      html: `<p>Your new OTP is <b>${otp}</b>. It is valid for 10 minutes.</p>`,
    });

    res.json({ message: 'New OTP sent successfully' });
  } catch (err) {
    console.error('Resend OTP error:', err.message);
    res.status(400).json({ message: err.message || 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));