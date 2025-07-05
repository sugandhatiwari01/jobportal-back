require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const multer = require('multer');
const { GridFSBucket } = require('mongodb');
const path = require('path');
const winston = require('winston');

const app = express();

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'combined.log') }),
    new winston.transports.Console(),
  ],
});

// Log all incoming requests
app.use((req, res, next) => {
  logger.info('Incoming request:', {
    method: req.method,
    url: req.url,
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers,
  });
  next();
});

// Block suspicious origins
app.use((req, res, next) => {
  const origin = req.get('Origin');
  if (origin && origin.includes('git.new')) {
    logger.warn('Blocked suspicious origin:', { origin });
    return res.status(403).json({ message: 'Blocked suspicious origin' });
  }
  next();
});

// Middleware
app.use(express.json());

// CORS Configuration
app.use(cors({
  origin: (origin, callback) => {
    logger.info('CORS Origin:', { origin });
    if (!origin || origin === 'http://localhost:5173' || origin.endsWith('.vercel.app')) {
      return callback(null, true);
    }
    logger.warn('Blocked origin:', { origin });
    callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Handle preflight requests
app.options('*', cors());

// Health Check Route
app.get('/health', (req, res) => {
  logger.info('Health check requested', {
    method: req.method,
    url: req.url,
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers,
  });
  res.json({ status: 'OK' });
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => logger.info('MongoDB connected'))
  .catch(err => logger.error('MongoDB connection error:', { error: err.message }));

const db = mongoose.connection;
let gfs;

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

// Initialize GridFS
db.once('open', () => {
  gfs = new GridFSBucket(db.db, { bucketName: 'cvs' });
  logger.info('GridFS initialized');
});

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  state: { type: String, required: true, default: 'Unknown' },
  city: { type: String, required: true, default: 'Unknown' },
  houseNoStreet: { type: String },
  cvFileId: { type: mongoose.Types.ObjectId, ref: 'cvs.files' },
  otp: { type: String },
  otpExpires: { type: Date },
  verified: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model('User', userSchema);

// Job Post Schema
const jobPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  location: { type: String, required: true },
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
});

const JobPost = mongoose.model('JobPost', jobPostSchema);

// Application Schema
const applicationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  jobPostId: { type: mongoose.Schema.Types.ObjectId, ref: 'JobPost', required: true },
  appliedAt: { type: Date, default: Date.now },
});

const Application = mongoose.model('Application', applicationSchema);

// US States for Validation
const usStates = [
  'Alabama', 'Alaska', 'Arizona', 'Arkansas', 'California', 'Colorado', 'Connecticut', 'Delaware',
  'Florida', 'Georgia', 'Hawaii', 'Idaho', 'Illinois', 'Indiana', 'Iowa', 'Kansas', 'Kentucky',
  'Louisiana', 'Maine', 'Maryland', 'Massachusetts', 'Michigan', 'Minnesota', 'Mississippi',
  'Missouri', 'Montana', 'Nebraska', 'Nevada', 'New Hampshire', 'New Jersey', 'New Mexico',
  'New York', 'North Carolina', 'North Dakota', 'Ohio', 'Oklahoma', 'Oregon', 'Pennsylvania',
  'Rhode Island', 'South Carolina', 'South Dakota', 'Tennessee', 'Texas', 'Utah', 'Vermont',
  'Virginia', 'Washington', 'West Virginia', 'Wisconsin', 'Wyoming'
];

// Validation Functions
const validateName = (name) => name && name.length >= 2;
const validateEmail = (email) => /\S+@\S+\.\S+/.test(email);
const validatePassword = (password) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password);
const validatePhone = (phone) => !phone || /^\d{10}$/.test(phone);
const validateState = (state) => state && usStates.includes(state);
const validateCity = (city) => city && city.length >= 2;
const validateHouseNoStreet = (houseNoStreet) => !houseNoStreet || houseNoStreet.length >= 5;
const validateJobPost = (title, description, location) =>
  title && title.length >= 3 && description && description.length >= 10 && location && location.length >= 2;

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    const user = await User.findById(req.userId);
    if (!user) return res.status(401).json({ message: 'User not found' });
    req.isAdmin = user.isAdmin;
    next();
  } catch (err) {
    logger.error('Auth error:', { error: err.message });
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  logger.info('Signup request:', { name, email });

  const errors = {};
  if (!validateName(name)) errors.name = 'Name must be at least 2 characters';
  if (!validateEmail(email)) errors.email = 'Invalid email format';
  if (!validatePassword(password))
    errors.password = 'Password must be 8+ characters with uppercase, lowercase, number, and special character';

  if (Object.keys(errors).length > 0) {
    logger.info('Validation errors:', { errors });
    return res.status(400).json({ errors });
  }

  try {
    const existingUser = await User.findOne({ email: email.trim().toLowerCase() });
    if (existingUser) {
      logger.info('Email already exists:', { email });
      return res.status(400).json({ message: 'Email already exists' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    logger.info('Generated OTP:', { otp });
    const hashedPassword = await bcrypt.hash(password.trim(), 10);
    const user = new User({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      password: hashedPassword,
      otp,
      otpExpires: Date.now() + 10 * 60 * 1000,
      state: 'Unknown',
      city: 'Unknown',
      isAdmin: req.body.isAdmin || false,
    });
    logger.info('Saving user:', { name: user.name, email: user.email, state: user.state, city: user.city });
    await user.save();
    logger.info('User saved:', { userId: user._id });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    logger.info('Sending email to:', { email });
    await transporter.sendMail({
      from: `"User Profile App" <${process.env.EMAIL_USER}>`,
      to: email.trim().toLowerCase(),
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}. It expires in 10 minutes.`,
    });
    logger.info('Email sent successfully');

    res.json({ message: 'OTP sent to email. Please verify.' });
  } catch (err) {
    logger.error('Signup error:', { error: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// OTP Verification
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  logger.info('Verify OTP request:', { email, otp });

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (user.verified) return res.status(400).json({ message: 'User already verified' });
    if (user.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });
    if (user.otpExpires < Date.now()) return res.status(400).json({ message: 'OTP expired' });

    user.verified = true;
    user.otp = null;
    user.otpExpires = null;
    await user.save();
    logger.info('User verified:', { userId: user._id });

    res.json({ message: 'Email verified successfully' });
  } catch (err) {
    logger.error('OTP verification error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  logger.info('Login request:', { email });

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });
    if (!user.verified) return res.status(400).json({ message: 'Email not verified' });

    const isMatch = await bcrypt.compare(password.trim(), user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    logger.info('Login successful:', { userId: user._id });
    res.json({ token, isAdmin: user.isAdmin });
  } catch (err) {
    logger.error('Login error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Profile Update with CV Upload
app.post('/api/profile', authenticate, upload.single('cv'), async (req, res) => {
  const { phone, state, city, houseNoStreet } = req.body;
  const cv = req.file;
  logger.info('Profile update request:', { userId: req.userId, phone, state, city, houseNoStreet, file: !!cv });

  const errors = {};
  if (!validatePhone(phone)) errors.phone = 'Phone must be a 10-digit number';
  if (!validateState(state)) errors.state = 'Invalid state';
  if (!validateCity(city)) errors.city = 'City must be at least 2 characters';
  if (!validateHouseNoStreet(houseNoStreet)) errors.houseNoStreet = 'Address must be at least 5 characters if provided';
  if (!cv) errors.cv = 'CV file is required';

  if (Object.keys(errors).length > 0) {
    logger.info('Validation errors:', { errors });
    return res.status(400).json({ message: 'Validation failed', errors });
  }

  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.cvFileId) {
      try {
        await gfs.delete(new mongoose.Types.ObjectId(user.cvFileId));
        logger.info('Deleted old CV:', { fileId: user.cvFileId });
      } catch (err) {
        logger.error('Error deleting old CV:', { error: err.message });
      }
    }

    const uploadStream = gfs.openUploadStream(cv.originalname, {
      contentType: cv.mimetype,
    });
    uploadStream.write(cv.buffer);
    uploadStream.end();

    const fileId = await new Promise((resolve, reject) => {
      uploadStream.on('finish', () => resolve(uploadStream.id));
      uploadStream.on('error', (err) => reject(err));
    });

    user.phone = phone || user.phone;
    user.state = state || user.state;
    user.city = city || user.city;
    user.houseNoStreet = houseNoStreet || user.houseNoStreet;
    user.cvFileId = fileId;

    await user.save();
    logger.info('Profile updated:', { userId: user._id });
    res.json({ message: 'Profile updated successfully', fileId });
  } catch (err) {
    logger.error('Profile update error:', { error: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get Profile
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('name email phone state city houseNoStreet cvFileId');
    if (!user) return res.status(404).json({ message: 'User not found' });
    logger.info('Profile fetched:', { userId: user._id });
    res.json(user);
  } catch (err) {
    logger.error('Get profile error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get CV File
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
      logger.error('Download stream error:', { error: err.message });
      res.status(500).json({ message: 'Error serving file' });
    });
  } catch (err) {
    logger.error('CV fetch error:', { error: err.message });
    res.status(400).json({ message: 'Invalid file ID' });
  }
});

// Admin: Get Users with CVs
app.get('/api/admin/users', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  try {
    const users = await User.find({ cvFileId: { $exists: true } })
      .select('name email phone state city houseNoStreet cvFileId');
    logger.info('Fetched users with CVs:', { count: users.length });
    res.json(users);
  } catch (err) {
    logger.error('Fetch users error:', { error: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: Create Job Post
app.post('/api/admin/job-posts', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const { title, description, location } = req.body;
  logger.info('Create job post request:', { title, location });

  const errors = {};
  if (!validateJobPost(title, description, location)) {
    errors.jobPost = 'Title (3+ chars), description (10+ chars), and location (2+ chars) are required';
  }

  if (Object.keys(errors).length > 0) {
    logger.info('Validation errors:', { errors });
    return res.status(400).json({ message: 'Validation failed', errors });
  }

  try {
    const jobPost = new JobPost({
      title: title.trim(),
      description: description.trim(),
      location: location.trim(),
      postedBy: req.userId,
    });
    await jobPost.save();
    await jobPost.populate('postedBy', 'name email');
    logger.info('Job post created:', { jobPostId: jobPost._id });
    res.json({ message: 'Job post created successfully', jobPost });
  } catch (err) {
    logger.error('Create job post error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: Get All Job Posts
app.get('/api/admin/job-posts', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  try {
    const jobPosts = await JobPost.find({ postedBy: req.userId })
      .populate('postedBy', 'name email');
    logger.info('Fetched job posts:', { count: jobPosts.length });
    res.json(jobPosts);
  } catch (err) {
    logger.error('Fetch job posts error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: Get Single Job Post
app.get('/api/admin/job-posts/:id', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  try {
    const jobPost = await JobPost.findOne({ _id: req.params.id, postedBy: req.userId })
      .populate('postedBy', 'name email');
    if (!jobPost) return res.status(404).json({ message: 'Job post not found or you are not authorized' });
    logger.info('Fetched job post:', { jobPostId: req.params.id });
    res.json(jobPost);
  } catch (err) {
    logger.error('Fetch job post error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Admin: Get Applications for a Job Post
app.get('/api/admin/job-posts/:id/applications', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  try {
    const jobPostId = req.params.id;
    const jobPost = await JobPost.findOne({ _id: jobPostId, postedBy: req.userId });
    if (!jobPost) return res.status(404).json({ message: 'Job post not found or you are not authorized to view its applications' });

    const applications = await Application.find({ jobPostId })
      .populate('userId', 'name email phone state city houseNoStreet cvFileId')
      .populate('jobPostId', 'title');
    logger.info('Fetched applications for job post:', { jobPostId, count: applications.length });
    res.json(applications);
  } catch (err) {
    logger.error('Fetch applications error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// User: Get All Job Posts
app.get('/api/jobs', async (req, res) => {
  try {
    const jobPosts = await JobPost.find().select('title description location createdAt');
    logger.info('Fetched job posts for users:', { count: jobPosts.length });
    res.json(jobPosts);
  } catch (err) {
    logger.error('Fetch jobs error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// User: Apply to Job Post
app.post('/api/jobs/apply/:id', authenticate, async (req, res) => {
  const jobPostId = req.params.id;
  logger.info('Job apply request:', { userId: req.userId, jobPostId });

  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (!user.verified) return res.status(400).json({ message: 'Email not verified' });
    if (!user.cvFileId) return res.status(400).json({ message: 'Please upload a CV in your profile' });

    const jobPost = await JobPost.findById(jobPostId);
    if (!jobPost) return res.status(404).json({ message: 'Job post not found' });

    const existingApplication = await Application.findOne({ userId: req.userId, jobPostId });
    if (existingApplication) {
      logger.info('User already applied:', { userId: req.userId, jobPostId });
      return res.status(400).json({ message: 'You have already applied to this job' });
    }

    const application = new Application({
      userId: req.userId,
      jobPostId,
    });
    await application.save();
    logger.info('Application submitted:', { applicationId: application._id });
    res.json({ message: 'Application submitted successfully' });
  } catch (err) {
    logger.error('Apply error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// User: Get Applied Job Posts
app.get('/api/user/applications', authenticate, async (req, res) => {
  try {
    const applications = await Application.find({ userId: req.userId })
      .populate('jobPostId', 'title description location');
    logger.info('Fetched user applications:', { userId: req.userId, count: applications.length });
    res.json(applications);
  } catch (err) {
    logger.error('Fetch user applications error:', { error: err.message });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Global Error Handler
app.use((err, req, res, next) => {
  logger.error('Global error:', {
    message: err.message,
    stack: err.stack,
    method: req.method || 'N/A',
    url: req.url || 'N/A',
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers || {},
  });
  res.status(500).json({ message: 'Server error', error: err.message });
});

// Start Server (for Render)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));

// Export for Vercel
module.exports = app;
