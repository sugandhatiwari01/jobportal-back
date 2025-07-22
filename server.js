require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const multer = require('multer');
const { GridFSBucket } = require('mongodb');
const paypal = require('paypal-rest-sdk');
const QRCode = require('qrcode');
const path = require('path');
const crypto = require('crypto');

const app = express();

paypal.configure({
  mode: 'sandbox',
  client_id: process.env.PAYPAL_CLIENT_ID,
  client_secret: process.env.PAYPAL_CLIENT_SECRET,
});

// Middleware to block suspicious URLs
app.use((req, res, next) => {
  const url = req.originalUrl || req.url || '';
  console.log('Incoming request:', {
    method: req.method,
    url,
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers,
  });
  if (url.includes('git.new') || url.includes('pathToRegexpError')) {
    console.warn('Blocked malformed URL:', { url, origin: req.get('Origin') || 'no-origin' });
    return res.status(400).json({ message: 'Invalid request URL' });
  }
  next();
});

// Middleware
app.use(express.json());

// CORS Configuration
app.use(cors({
  origin: (origin, callback) => {
    console.log('CORS Origin check:', { origin });
    if (!origin || origin === 'http://localhost:5173' || /\.vercel\.app$/.test(origin) || origin === 'https://jobportal-front-beta.vercel.app' || origin === 'https://staffing.centennialinfotech.com') {
      return callback(null, true);
    }
    console.warn('Blocked origin:', { origin });
    callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.options('*', cors());

// Root Route
app.all('/', (req, res) => {
  console.log('Root route accessed:', {
    method: req.method,
    url: req.url,
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers,
  });
  res.json({ message: 'Welcome to the Job Portal API' });
});

// Health Check Route
app.get('/health', (req, res) => {
  console.log('Health check requested:', {
    method: req.method,
    url: req.url,
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers,
  });
  res.json({ status: 'OK' });
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err.message));

const db = mongoose.connection;
let gfs;

// Multer configuration
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const logoAllowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    console.log('Multer file received:', {
      fieldname: file.fieldname,
      mimetype: file.mimetype,
      originalname: file.originalname,
      size: file.size,
    });
    if (
      file.fieldname === 'companyLogo' &&
      (!logoAllowedTypes.includes(file.mimetype) || !allowedExts.includes(ext))
    ) {
      return cb(
        new Error('Invalid file type for company logo. Only JPEG, PNG, GIF, or WebP allowed.'),
        false
      );
    }
    if (file.size > 2 * 1024 * 1024) {
      return cb(new Error('File size must be less than 2MB.'), false);
    }
    // Remove the strict size check for undefined or zero
    cb(null, true);
  },
});

// Multer error handling middleware
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('Multer error:', { message: err.message, field: err.field });
    return res.status(400).json({ message: 'File upload error', error: err.message });
  }
  if (err) {
    console.error('File filter error:', { message: err.message });
    return res.status(400).json({ message: 'File validation failed', error: err.message });
  }
  next();
};

// Initialize GridFS
db.once('open', () => {
  gfs = new GridFSBucket(db.db, { bucketName: 'cvs' });
  console.log('GridFS initialized');
});

// Subscription Schema
const subscriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  plan: { 
    type: String, 
    enum: ['free', 'basic', 'standard', 'premium', 'enterprise'], 
    required: true 
  },
  applicantLimit: { type: Number, required: true },
  paypalPaymentId: { type: String },
  createdAt: { type: Date, default: Date.now },
});
const Subscription = mongoose.model('Subscription', subscriptionSchema);

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
  companyName: { type: String },
  companyPhone: { type: String },
  companyLogo: { type: mongoose.Types.ObjectId, ref: 'cvs.files' },
  otp: { type: String },
  otpExpires: { type: Date },
  verified: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  subscription: { type: mongoose.Schema.Types.ObjectId, ref: 'Subscription' },
  resetPasswordToken: { type: String }, // New field for reset token
  resetPasswordExpires: { type: Date }, // New field for token expiration
skills: [{ type: String }] // Add this line
});
const User = mongoose.model('User', userSchema);

// Job Post Schema

// Job Post Schema
// Job Post Schema
const jobPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  location: { type: String, required: true },
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  skills: [{ type: String }],
  workType: {
    type: String,
    required: true,
    enum: ['Remote', 'Hybrid', 'Onsite'],
    default: 'Remote', // Optional: set a default value
  },
screeningQuestions: [{ type: String }],
});
const JobPost = mongoose.model('JobPost', jobPostSchema);


// Application Schema
const applicationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  jobPostId: { type: mongoose.Schema.Types.ObjectId, ref: 'JobPost', required: true },
  appliedAt: { type: Date, default: Date.now },
  screeningAnswers: [{ type: String }], // Changed to an array of strings
});
const Application = mongoose.model('Application', applicationSchema);

// US States
const usStates = [
  'Alabama', 'Alaska', 'Arizona', 'Arkansas', 'California', 'Colorado', 'Connecticut', 'Delaware',
  'Florida', 'Georgia', 'Hawaii', 'Idaho', 'Illinois', 'Indiana', 'Iowa', 'Kansas', 'Kentucky',
  'Louisiana', 'Maine', 'Maryland', 'Massachusetts', 'Michigan', 'Minnesota', 'Mississippi',
  'Missouri', 'Montana', 'Nebraska', 'Nevada', 'New Hampshire', 'New Jersey', 'New Mexico',
  'New York', 'North Carolina', 'North Dakota', 'Ohio', 'Oklahoma', 'Oregon', 'Pennsylvania',
  'Rhode Island', 'South Carolina', 'South Dakota', 'Tennessee', 'Texas', 'Utah', 'Vermont',
  'Virginia', 'Washington', 'West Virginia', 'Wisconsin', 'Wyoming'
];

// Subscription Plans
const subscriptionPlans = {
  free: { applicantLimit: 1, price: 0.00 },
  basic: { applicantLimit: 100, price: 10.00 },
  standard: { applicantLimit: 200, price: 20.00 },
  premium: { applicantLimit: 500, price: 50.00 },
  enterprise: { applicantLimit: 1000, price: 100.00 },
};

// Validation Functions
const validateName = (name) => name && name.length >= 2;
const validateEmail = (email) => /\S+@\S+\.\S+/.test(email);
const validatePassword = (password) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password);
const validatePhone = (phone) => !phone || /^\+?\d{10,15}$/.test(phone);
const validateState = (state) => state && usStates.includes(state);
const validateCity = (city) => city && city.length >= 2;
const validateHouseNoStreet = (houseNoStreet) => !houseNoStreet || houseNoStreet.length >= 5;
const validateJobPost = (title, description, location, workType) =>
  title && title.length >= 3 &&
  description && description.length >= 10 &&
  location && location.length >= 2 &&
  workType && ['Remote', 'Hybrid', 'Onsite'].includes(workType);

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
    console.error('Auth error:', err.message);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes
try {
  // Update the /api/subscription/current endpoint
app.get('/api/subscription/current', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).populate('subscription');
    if (!user) {
      console.warn('User not found for subscription fetch:', req.userId);
      return res.status(404).json({ message: 'User not found' });
    }
    if (!user.subscription) {
      console.log('No subscription found for user:', req.userId);
      return res.json({ plan: null, isActive: false, isAdmin: user.isAdmin });
    }
    const subscription = user.subscription;
    console.log('Fetched subscription:', { userId: req.userId, plan: subscription.plan, isAdmin: user.isAdmin });
    res.json({
      plan: subscription.plan,
      isActive: subscription.plan !== 'free',
      isAdmin: user.isAdmin,
    });
  } catch (err) {
    console.error('Get subscription error:', {
      message: err.message,
      stack: err.stack,
      userId: req.userId,
    });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
  // Create or Update Subscription
app.post('/api/subscription/checkout', authenticate, async (req, res) => {
  const { plan } = req.body;
  console.log('Subscription checkout request:', { userId: req.userId, plan });

  if (!subscriptionPlans[plan]) {
    console.warn('Invalid plan:', plan);
    return res.status(400).json({ message: 'Invalid plan selected' });
  }

  try {
    const user = await User.findById(req.userId);
    if (!user) {
      console.warn('User not found:', req.userId);
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if admin has completed profile (companyName and companyLogo)
    if (user.isAdmin && (!user.companyName || !user.companyLogo)) {
      console.warn('Incomplete admin profile:', { userId: req.userId, companyName: !!user.companyName, companyLogo: !!user.companyLogo });
      return res.status(400).json({ message: 'Please complete your company profile (name and logo) before subscribing.' });
    }

    if (plan === 'free') {
      let subscription = await Subscription.findOne({ userId: req.userId });
      try {
        if (subscription) {
          subscription.plan = 'free';
          subscription.applicantLimit = subscriptionPlans.free.applicantLimit;
          subscription.paypalPaymentId = null;
          await subscription.save();
          console.log('Updated subscription to free trial:', { subscriptionId: subscription._id, applicantLimit: subscription.applicantLimit });
        } else {
          subscription = new Subscription({
            userId: req.userId,
            plan: 'free',
            applicantLimit: subscriptionPlans.free.applicantLimit,
            paypalPaymentId: null,
          });
          await subscription.save();
          user.subscription = subscription._id;
          console.log('Created new free trial subscription:', { subscriptionId: subscription._id, applicantLimit: subscription.applicantLimit });
        }
        user.isAdmin = true;
        await user.save();
        console.log('Free trial activated:', { userId: req.userId, isAdmin: user.isAdmin, subscriptionId: user.subscription });
      } catch (err) {
        console.error('Error saving subscription or user:', {
          message: err.message,
          stack: err.stack,
          userId: req.userId,
          plan,
        });
        return res.status(500).json({ message: 'Failed to activate free trial due to database error', error: err.message });
      }
      return res.json({ message: 'Free trial activated successfully', plan: 'free', isAdmin: user.isAdmin });
    }

    if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET) {
      console.error('PayPal configuration missing:', {
        clientId: !!process.env.PAYPAL_CLIENT_ID,
        clientSecret: !!process.env.PAYPAL_CLIENT_SECRET,
      });
      return res.status(500).json({ message: 'Server configuration error: Missing PayPal credentials' });
    }
    if (!process.env.FRONTEND_URL) {
      console.error('FRONTEND_URL missing');
      return res.status(500).json({ message: 'Server configuration error: Missing FRONTEND_URL' });
    }

    const currency = 'USD';
    const payment = {
      intent: 'sale',
      payer: { payment_method: 'paypal' },
      redirect_urls: {
        return_url: `${process.env.FRONTEND_URL}/subscription/success`,
        cancel_url: `${process.env.FRONTEND_URL}/subscription/cancel`,
      },
      transactions: [{
        amount: {
          currency: currency,
          total: subscriptionPlans[plan].price.toFixed(2),
        },
        description: `${plan.charAt(0).toUpperCase() + plan.slice(1)} Plan - ${subscriptionPlans[plan].applicantLimit} applicants per job post`,
        custom: JSON.stringify({ userId: req.userId.toString(), plan }),
      }],
    };

    const paymentResult = await new Promise((resolve, reject) => {
      paypal.payment.create(payment, (error, payment) => {
        if (error) {
          console.error('PayPal payment.create error:', JSON.stringify(error, null, 2));
          reject(error);
        } else {
          resolve(payment);
        }
      });
    });

    const approvalUrl = paymentResult.links.find(link => link.rel === 'approval_url')?.href;
    if (!approvalUrl) {
      console.error('No approval URL in PayPal response:', paymentResult);
      return res.status(500).json({ message: 'Failed to get PayPal approval URL' });
    }

    const qrCode = await QRCode.toDataURL(approvalUrl);
    console.log('PayPal payment created:', { paymentId: paymentResult.id, approvalUrl, currency });

    res.json({ paymentId: paymentResult.id, qrCode, approvalUrl });
  } catch (err) {
    console.error('Checkout error:', {
      message: err.message,
      stack: err.stack,
      status: err.response?.status,
      details: err.response?.data,
    });
    res.status(500).json({ message: 'Server error during subscription activation', error: err.message });
  }
});


  // Verify Payment and Update Subscription
  app.post('/api/subscription/verify', authenticate, async (req, res) => {
    const { paymentId, payerId } = req.body;
    console.log('Subscription verify request:', { userId: req.userId, paymentId, payerId });

    try {
      const paymentPromise = new Promise((resolve, reject) => {
        paypal.payment.get(paymentId, (error, payment) => {
          if (error) {
            reject(error);
          } else {
            resolve(payment);
          }
        });
      });

      const payment = await paymentPromise;
      if (payment.state !== 'created') {
        console.warn('Payment already processed:', paymentId);
        return res.status(400).json({ message: 'Payment already processed' });
      }

      const custom = JSON.parse(payment.transactions[0].custom);
      if (custom.userId !== req.userId.toString()) {
        console.warn('User ID mismatch:', { paymentUserId: custom.userId, reqUserId: req.userId });
        return res.status(403).json({ message: 'Unauthorized' });
      }

      const plan = custom.plan;
      if (!subscriptionPlans[plan]) {
        console.warn('Invalid plan in payment:', plan);
        return res.status(400).json({ message: 'Invalid plan' });
      }

      const executePromise = new Promise((resolve, reject) => {
        paypal.payment.execute(paymentId, { payer_id: payerId }, (error, payment) => {
          if (error) {
            reject(error);
          } else {
            resolve(payment);
          }
        });
      });

      const executedPayment = await executePromise;
      if (executedPayment.state !== 'approved') {
        console.warn('Payment not approved:', paymentId);
        return res.status(400).json({ message: 'Payment not approved' });
      }

      const user = await User.findById(req.userId);
      let subscription = await Subscription.findOne({ userId: req.userId });
      if (subscription) {
        subscription.plan = plan;
        subscription.applicantLimit = subscriptionPlans[plan].applicantLimit;
        subscription.paypalPaymentId = paymentId;
        await subscription.save();
      } else {
        subscription = new Subscription({
          userId: req.userId,
          plan,
          applicantLimit: subscriptionPlans[plan].applicantLimit,
          paypalPaymentId: paymentId,
        });
        await subscription.save();
        user.subscription = subscription._id;
      }
      user.isAdmin = plan !== 'free';
      await user.save();

      console.log('Subscription activated:', { userId: req.userId, plan, subscriptionId: subscription._id });
      res.json({ message: 'Subscription activated successfully', plan });
    } catch (err) {
      console.error('Subscription verify error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Job Application Endpoint
// Replace the existing /api/jobs/apply/:id endpoint
app.post('/api/jobs/apply/:id', authenticate, async (req, res) => {
  const jobPostId = req.params.id;
  console.log('Job apply request:', { userId: req.userId, jobPostId });

  try {
    if (!mongoose.Types.ObjectId.isValid(jobPostId)) {
      return res.status(400).json({ message: 'Invalid job post ID format' });
    }
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (!user.verified) return res.status(400).json({ message: 'Email not verified' });
    if (!user.cvFileId) return res.status(400).json({ message: 'Please upload a CV in your profile' });

    const jobPost = await JobPost.findById(jobPostId);
    if (!jobPost) return res.status(404).json({ message: 'Job post not found' });
    if (!jobPost.isActive) return res.status(400).json({ message: 'This job post is no longer accepting applications' });

    const existingApplication = await Application.findOne({ userId: req.userId, jobPostId });
    if (existingApplication) {
      return res.status(400).json({ message: 'You have already applied to this job' });
    }

    const admin = await User.findById(jobPost.postedBy);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    const subscription = await Subscription.findOne({ userId: admin._id });
    if (!subscription) return res.status(400).json({ message: 'Admin has no active subscription' });

    const applicationCount = await Application.countDocuments({ jobPostId });
    if (applicationCount >= subscription.applicantLimit) {
      jobPost.isActive = false;
      await jobPost.save();
      return res.status(400).json({ message: 'Applicant limit reached for this job post' });
    }

    const { screeningAnswers } = req.body;
    if (jobPost.screeningQuestions && jobPost.screeningQuestions.length > 0) {
      if (!screeningAnswers || !Array.isArray(screeningAnswers) || screeningAnswers.length !== jobPost.screeningQuestions.length) {
        return res.status(400).json({ message: 'Screening answers must be an array matching the number of questions' });
      }
      if (screeningAnswers.some(a => !a || a.trim().length < 1)) {
        return res.status(400).json({ message: 'All screening answers must be non-empty strings' });
      }
    }

    const application = new Application({
      userId: req.userId,
      jobPostId,
      screeningAnswers: screeningAnswers || [], // Store as an array
    });
    await application.save();

    const newApplicationCount = await Application.countDocuments({ jobPostId });
    if (newApplicationCount >= subscription.applicantLimit) {
      jobPost.isActive = false;
      await jobPost.save();
    }

    res.json({ message: 'Application submitted successfully' });
  } catch (err) {
    console.error('Apply error:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
  // Signup
  app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    console.log('Signup request:', { name, email });

    const errors = {};
    if (!validateName(name)) errors.name = 'Name must be at least 2 characters';
    if (!validateEmail(email)) errors.email = 'Invalid email format';
    if (!validatePassword(password))
      errors.password = 'Password must be 8+ characters with uppercase, lowercase, number, and special character';

    if (Object.keys(errors).length > 0) {
      console.log('Validation errors:', errors);
      return res.status(400).json({ errors });
    }

    try {
      const existingUser = await User.findOne({ email: email.trim().toLowerCase() });
      if (existingUser) {
        console.log('Email already exists:', email);
        return res.status(400).json({ message: 'Email already exists' });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      console.log('Generated OTP:', otp);
      const hashedPassword = await bcrypt.hash(password.trim(), 10);
      const user = new User({
        name: name.trim(),
        email: email.trim().toLowerCase(),
        password: hashedPassword,
        otp,
        otpExpires: Date.now() + 10 * 60 * 1000,
        state: 'Unknown',
        city: 'Unknown',
        isAdmin: false,
        subscription: null,
      });
      await user.save();

      console.log('User saved:', { userId: user._id });

      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });

      console.log('Sending email to:', email);
      await transporter.sendMail({
        from: `"User Profile App" <${process.env.EMAIL_USER}>`,
        to: email.trim().toLowerCase(),
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It expires in 10 minutes.`,
      });
      console.log('Email sent successfully');

      res.json({ message: 'OTP sent to email. Please verify.' });
    } catch (err) {
      console.error('Signup error:', err.message, err.stack);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Admin Signup
  app.post('/api/admin/signup', async (req, res) => {
    const { name, email, password } = req.body;
    console.log('Admin signup request:', { name, email });

    const errors = {};
    if (!validateName(name)) errors.name = 'Name must be at least 2 characters';
    if (!validateEmail(email)) errors.email = 'Invalid email format';
    if (!validatePassword(password))
      errors.password = 'Password must be 8+ characters with uppercase, lowercase, number, and special character';

    if (Object.keys(errors).length > 0) {
      console.log('Validation errors:', errors);
      return res.status(400).json({ errors });
    }

    try {
      const existingUser = await User.findOne({ email: email.trim().toLowerCase() });
      if (existingUser) {
        console.log('Email already exists:', email);
        return res.status(400).json({ message: 'Email already exists' });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      console.log('Generated OTP:', otp);
      const hashedPassword = await bcrypt.hash(password.trim(), 10);
      const user = new User({
        name: name.trim(),
        email: email.trim().toLowerCase(),
        password: hashedPassword,
        otp,
        otpExpires: Date.now() + 10 * 60 * 1000,
        state: 'Unknown',
        city: 'Unknown',
        isAdmin: true,
        subscription: null,
      });
      await user.save();

      console.log('Admin user saved:', { userId: user._id });

      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });

      console.log('Sending email to:', email);
      await transporter.sendMail({
        from: `"Job Portal" <${process.env.EMAIL_USER}>`,
        to: email.trim().toLowerCase(),
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It expires in 10 minutes.`,
      });
      console.log('Email sent successfully');

      res.json({ message: 'OTP sent to email. Please verify.' });
    } catch (err) {
      console.error('Admin signup error:', err.message, err.stack);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // OTP Verification
  app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    console.log('Verify OTP request:', { email, otp });

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
      console.log('User verified:', user._id);

      res.json({ message: 'Email verified successfully' });
    } catch (err) {
      console.error('OTP verification error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Login
  app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login request:', { email });

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      console.warn('User not found:', email);
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    if (!user.verified) {
      console.warn('Email not verified:', email);
      return res.status(400).json({ message: 'Email not verified' });
    }
    if (user.isAdmin) {
      console.warn('Admin attempted to login via user endpoint:', { email });
      return res.status(403).json({ message: 'Admin accounts must use the admin login endpoint' });
    }

    const isMatch = await bcrypt.compare(password.trim(), user.password);
    if (!isMatch) {
      console.warn('Invalid password for:', email);
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    console.log('Login successful:', { userId: user._id });
    res.json({ token, isAdmin: user.isAdmin });
  } catch (err) {
    console.error('Login error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

  // Admin Login
  app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Admin login request:', { email });
  try {
    if (!email || !password) {
      console.warn('Missing email or password:', { email, hasPassword: !!password });
      return res.status(400).json({ message: 'Email and password are required' });
    }
    if (!mongoose.connection.readyState) {
      console.error('MongoDB not connected');
      return res.status(500).json({ message: 'Database connection error' });
    }
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET not configured');
      return res.status(500).json({ message: 'Server configuration error: Missing JWT_SECRET' });
    }
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      console.warn('User not found:', email);
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    if (!user.verified) {
      console.warn('Email not verified:', email);
      return res.status(400).json({ message: 'Email not verified' });
    }
    if (!user.isAdmin) {
      console.warn('Not an admin account:', email);
      return res.status(403).json({ message: 'Not an admin account' });
    }
    const isMatch = await bcrypt.compare(password.trim(), user.password);
    if (!isMatch) {
      console.warn('Invalid password for:', email);
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin, loginType: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    console.log('Admin login successful:', user._id);
    res.json({ token, userId: user._id, isAdmin: user.isAdmin, loginType: 'admin' });
  } catch (err) {
    console.error('Admin login error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error during login', error: err.message || 'Unknown error' });
  }
});

  // Profile Update with CV/Logo Upload
// Profile Update with CV/Logo Upload (POST and PUT)
// Profile Update with CV/Logo Upload (POST)
app.post('/api/profile', authenticate, upload.fields([{ name: 'cv' }, { name: 'companyLogo' }]), handleMulterError, async (req, res) => {
  const { name, phone, state, city, houseNoStreet, companyName, companyPhone, skills } = req.body;
  const { cv, companyLogo } = req.files || {};
  console.log('Profile update request (POST):', { 
    userId: req.userId, 
    name, 
    phone, 
    state, 
    city, 
    houseNoStreet, 
    companyName, 
    companyPhone, 
    skills, // Log skills
    cv: !!cv, 
    companyLogo: !!companyLogo 
  });

  const errors = {};
  if (!req.isAdmin) {
    if (!validateName(name)) errors.name = 'Name must be at least 2 characters';
    if (!validatePhone(phone)) errors.phone = 'Phone must be a 10-15 digit number, optionally starting with +';
    if (!validateState(state)) errors.state = 'Invalid state';
    if (!validateCity(city)) errors.city = 'City must be at least 2 characters';
    if (!validateHouseNoStreet(houseNoStreet)) errors.houseNoStreet = 'Address must be at least 5 characters if provided';
    if (!cv) errors.cv = 'CV file is required';
    if (skills) {
      try {
        const parsedSkills = JSON.parse(skills); // Assuming skills is sent as a JSON string
        if (!Array.isArray(parsedSkills) || parsedSkills.some(s => !validateName(s))) {
          errors.skills = 'Skills must be an array of strings, each at least 2 characters';
        }
      } catch (err) {
        errors.skills = 'Invalid skills format; must be a JSON array of strings';
      }
    }
  } else {
    if (!validateName(companyName)) errors.companyName = 'Company name must be at least 2 characters';
    if (!validateState(state)) errors.state = 'Invalid state';
    if (!validateCity(city)) errors.city = 'City must be at least 2 characters';
    if (!validatePhone(companyPhone)) errors.companyPhone = 'Company phone must be a 10-15 digit number, optionally starting with +';
  }

  if (Object.keys(errors).length > 0) {
    console.log('Validation errors:', errors);
    return res.status(400).json({ message: 'Validation failed', errors });
  }

  try {
    const user = await User.findById(req.userId);
    if (!user) {
      console.warn('User not found:', req.userId);
      return res.status(404).json({ message: 'User not found' });
    }

    if (!req.isAdmin) {
      if (user.cvFileId && cv) {
        try {
          await gfs.delete(new mongoose.Types.ObjectId(user.cvFileId));
          console.log('Deleted old CV:', user.cvFileId);
        } catch (err) {
          console.error('Error deleting old CV:', { message: err.message, stack: err.stack });
        }
      }
      if (cv) {
        const uploadStream = gfs.openUploadStream(cv.originalname, { contentType: cv.mimetype });
        uploadStream.write(cv.buffer);
        uploadStream.end();
        user.cvFileId = await new Promise((resolve, reject) => {
          uploadStream.on('finish', () => resolve(uploadStream.id));
          uploadStream.on('error', (err) => reject(err));
        });
      }
      user.name = name || user.name;
      user.phone = phone || user.phone;
      user.state = state || user.state;
      user.city = city || user.city;
      user.houseNoStreet = houseNoStreet || user.houseNoStreet;
      if (skills) {
        user.skills = JSON.parse(skills); // Update skills
        console.log('Updated user skills:', user.skills);
      }
    } else {
      if (user.companyLogo && companyLogo) {
        try {
          await gfs.delete(new mongoose.Types.ObjectId(user.companyLogo));
          console.log('Deleted old company logo:', user.companyLogo);
        } catch (err) {
          console.error('Error deleting old company logo:', { message: err.message, stack: err.stack });
        }
      }
      if (companyLogo) {
        const uploadStream = gfs.openUploadStream(companyLogo.originalname, { contentType: companyLogo.mimetype });
        uploadStream.write(companyLogo.buffer);
        uploadStream.end();
        user.companyLogo = await new Promise((resolve, reject) => {
          uploadStream.on('finish', () => resolve(uploadStream.id));
          uploadStream.on('error', (err) => reject(err));
        });
      }
      user.name = companyName || user.name;
      user.companyName = companyName || user.companyName;
      user.state = state || user.state;
      user.city = city || user.city;
      user.companyPhone = companyPhone || user.companyPhone;
    }

    await user.save();
    console.log('Profile updated:', user._id);
    res.json({ message: 'Profile updated successfully', fileId: cv ? user.cvFileId : user.companyLogo });
  } catch (err) {
    console.error('Profile update error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// Add PUT route for profile updates
app.put('/api/profile', authenticate, upload.fields([{ name: 'cv' }, { name: 'companyLogo' }]), handleMulterError, async (req, res) => {
  const { name, phone, state, city, houseNoStreet, companyName, companyPhone, skills } = req.body;
  const { cv, companyLogo } = req.files || {};
  console.log('Profile update request (PUT):', {
    userId: req.userId,
    name,
    phone,
    state,
    city,
    houseNoStreet,
    companyName,
    companyPhone,
    skills, // Log skills
    cv: !!cv,
    companyLogo: companyLogo
      ? { originalname: companyLogo[0]?.originalname, mimetype: companyLogo[0]?.mimetype, size: companyLogo[0]?.size, hasBuffer: !!companyLogo[0]?.buffer }
      : null,
  });

  if (!gfs) {
    console.error('GridFS not initialized');
    return res.status(500).json({ message: 'Server error: GridFS not initialized' });
  }

  const errors = {};
  if (!req.isAdmin) {
    if (!validateName(name)) errors.name = 'Name must be at least 2 characters';
    if (!validatePhone(phone)) errors.phone = 'Phone must be a 10-15 digit number, optionally starting with +';
    if (!validateState(state)) errors.state = 'Invalid state';
    if (!validateCity(city)) errors.city = 'City must be at least 2 characters';
    if (!validateHouseNoStreet(houseNoStreet)) errors.houseNoStreet = 'Address must be at least 5 characters if provided';
    if (skills) {
      try {
        const parsedSkills = JSON.parse(skills); // Assuming skills is sent as a JSON string
        if (!Array.isArray(parsedSkills) || parsedSkills.some(s => !validateName(s))) {
          errors.skills = 'Skills must be an array of strings, each at least 2 characters';
        }
      } catch (err) {
        errors.skills = 'Invalid skills format; must be a JSON array of strings';
      }
    }
  } else {
    if (!validateName(companyName)) errors.companyName = 'Company name must be at least 2 characters';
    if (!validateState(state)) errors.state = 'Invalid state';
    if (!validateCity(city)) errors.city = 'City must be at least 2 characters';
    if (!validatePhone(companyPhone)) errors.companyPhone = 'Company phone must be a 10-15 digit number, optionally starting with +';
  }

  if (Object.keys(errors).length > 0) {
    console.log('Validation errors:', errors);
    return res.status(400).json({ message: 'Validation failed', errors });
  }

  try {
    const user = await User.findById(req.userId);
    if (!user) {
      console.warn('User not found:', req.userId);
      return res.status(404).json({ message: 'User not found' });
    }

    if (!req.isAdmin) {
      if (user.cvFileId && cv && cv[0]) {
        try {
          await gfs.delete(new mongoose.Types.ObjectId(user.cvFileId));
          console.log('Deleted old CV:', user.cvFileId);
        } catch (err) {
          console.error('Error deleting old CV:', { message: err.message, stack: err.stack });
        }
      }
      if (cv && cv[0]) {
        if (!cv[0].buffer || cv[0].buffer.length === 0) {
          console.error('Invalid CV file: No buffer or empty');
          return res.status(400).json({ message: 'Invalid CV file: No data or empty' });
        }
        const uploadStream = gfs.openUploadStream(cv[0].originalname, { contentType: cv[0].mimetype });
        uploadStream.write(cv[0].buffer);
        uploadStream.end();
        user.cvFileId = await new Promise((resolve, reject) => {
          uploadStream.on('finish', () => resolve(uploadStream.id));
          uploadStream.on('error', (err) => reject(err));
        });
      }
      user.name = name || user.name;
      user.phone = phone || user.phone;
      user.state = state || user.state;
      user.city = city || user.city;
      user.houseNoStreet = houseNoStreet || user.houseNoStreet;
      if (skills) {
        user.skills = JSON.parse(skills); // Update skills
        console.log('Updated user skills:', user.skills);
      }
    } else {
      if (user.companyLogo && companyLogo && companyLogo[0]) {
        try {
          await gfs.delete(new mongoose.Types.ObjectId(user.companyLogo));
          console.log('Deleted old company logo:', user.companyLogo);
        } catch (err) {
          console.error('Error deleting old company logo:', { message: err.message, stack: err.stack });
        }
      }
      if (companyLogo && companyLogo[0]) {
        if (!companyLogo[0].buffer || companyLogo[0].buffer.length === 0) {
          console.error('Invalid company logo file: No buffer or empty', {
            originalname: companyLogo[0].originalname,
            mimetype: companyLogo[0].mimetype,
            size: companyLogo[0].size,
          });
          return res.status(400).json({ message: 'Invalid company logo file: No data or empty' });
        }
        const uploadStream = gfs.openUploadStream(companyLogo[0].originalname, {
          contentType: companyLogo[0].mimetype,
        });
        uploadStream.write(companyLogo[0].buffer);
        uploadStream.end();
        user.companyLogo = await new Promise((resolve, reject) => {
          uploadStream.on('finish', () => resolve(uploadStream.id));
          uploadStream.on('error', (err) => reject(err));
        });
        console.log('Company logo uploaded to GridFS:', user.companyLogo);
      }
      user.name = companyName || user.name;
      user.companyName = companyName || user.companyName;
      user.state = state || user.state;
      user.city = city || user.city;
      user.companyPhone = companyPhone || user.companyPhone;
    }

    await user.save();
    console.log('Profile updated:', user._id);
    res.json({ message: 'Profile updated successfully', fileId: cv ? user.cvFileId : user.companyLogo });
  } catch (err) {
    console.error('Profile update error:', {
      message: err.message,
      stack: err.stack,
      fileDetails: companyLogo && companyLogo[0]
        ? { originalname: companyLogo[0].originalname, mimetype: companyLogo[0].mimetype, size: companyLogo[0].size }
        : null,
    });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// Admin: Update Job Post
// Admin: Update Job Post
app.put('/api/admin/job-posts/:id', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const jobPostId = req.params.id;
  const { title, description, location, skills, screeningQuestions, workType } = req.body;
  console.log('Update job post request:', { userId: req.userId, jobPostId, title, location, skills, screeningQuestions, workType });

  if (!mongoose.Types.ObjectId.isValid(jobPostId)) {
    console.warn('Invalid jobPostId format:', jobPostId);
    return res.status(400).json({ message: 'Invalid job post ID format' });
  }

  const errors = {};
  if (!validateJobPost(title, description, location, workType)) {
    errors.jobPost = 'Title (3+ chars), description (10+ chars), location (2+ chars), and valid workType (Remote, Hybrid, Onsite) are required';
  }
  if (skills) {
    try {
      const parsedSkills = JSON.parse(skills);
      if (!Array.isArray(parsedSkills) || parsedSkills.some(s => !s || s.trim().length < 2)) {
        errors.skills = 'Skills must be an array of non-empty strings, each at least 2 characters';
      }
    } catch (err) {
      errors.skills = 'Invalid skills format; must be a JSON array of strings';
    }
  }
  if (screeningQuestions) {
    try {
      const parsedQuestions = JSON.parse(screeningQuestions);
      if (!Array.isArray(parsedQuestions) || parsedQuestions.length > 5) {
        errors.screeningQuestions = 'Screening questions must be an array with a maximum of 5 entries';
      } else if (parsedQuestions.some(q => !q || q.trim().length < 1)) {
        errors.screeningQuestions = 'Each screening question must be a non-empty string';
      }
    } catch (err) {
      errors.screeningQuestions = 'Invalid screening questions format; must be a JSON array of strings';
    }
  }

  if (Object.keys(errors).length > 0) {
    console.log('Validation errors:', errors);
    return res.status(400).json({ message: 'Validation failed', errors });
  }

  try {
    const user = await User.findById(req.userId);
    if (!user) {
      console.warn('User not found:', req.userId);
      return res.status(404).json({ message: 'User not found' });
    }
    if (!user.companyName || !user.companyLogo) {
      console.warn('Incomplete admin profile for job update:', {
        userId: req.userId,
        companyName: !!user.companyName,
        companyLogo: !!user.companyLogo,
      });
      return res.status(400).json({ message: 'Please complete your company profile (name and logo) before updating a job post' });
    }

    const jobPost = await JobPost.findOne({ _id: jobPostId, postedBy: req.userId });
    if (!jobPost) {
      console.warn('Job post not found or unauthorized:', { jobPostId, userId: req.userId });
      return res.status(404).json({ message: 'Job post not found or you are not authorized to update it' });
    }

    jobPost.title = title.trim();
    jobPost.description = description.trim();
    jobPost.location = location.trim();
    jobPost.skills = skills ? JSON.parse(skills) : jobPost.skills || [];
    jobPost.screeningQuestions = screeningQuestions ? JSON.parse(screeningQuestions) : jobPost.screeningQuestions || [];
    jobPost.workType = workType.trim(); // Update workType
    await jobPost.save();
    await jobPost.populate('postedBy', 'name email companyName companyLogo');
    console.log('Job post updated:', { id: jobPost._id, skills: jobPost.skills, screeningQuestions: jobPost.screeningQuestions, workType: jobPost.workType });
    res.json({ message: 'Job post updated successfully', jobPost });
  } catch (err) {
    console.error('Update job post error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// Admin: Delete Job Post
app.delete('/api/admin/job-posts/:id', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const jobPostId = req.params.id;
  console.log('Delete job post request:', { userId: req.userId, jobPostId });

  if (!mongoose.Types.ObjectId.isValid(jobPostId)) {
    console.warn('Invalid jobPostId format:', jobPostId);
    return res.status(400).json({ message: 'Invalid job post ID format' });
  }

  try {
    const jobPost = await JobPost.findOneAndDelete({ _id: jobPostId, postedBy: req.userId });
    if (!jobPost) {
      console.warn('Job post not found or unauthorized:', { jobPostId, userId: req.userId });
      return res.status(404).json({ message: 'Job post not found or you are not authorized to delete it' });
    }

    // Optionally, delete associated applications
    await Application.deleteMany({ jobPostId });
    console.log('Job post and associated applications deleted:', jobPostId);
    res.json({ message: 'Job post deleted successfully' });
  } catch (err) {
    console.error('Delete job post error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// Get Profile
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select(
      'name email phone state city houseNoStreet cvFileId companyName companyPhone companyLogo isAdmin skills' // Include skills
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    console.log('Profile fetched:', user._id);
    res.json(user);
  } catch (err) {
    console.error('Get profile error:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
// Add this new route for admins
app.get('/api/admin/applications/:jobPostId', authenticate, async (req, res) => {
  try {
    if (!req.user.role === 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

    const jobPostId = req.params.jobPostId;
    if (!mongoose.Types.ObjectId.isValid(jobPostId)) {
      return res.status(400).json({ message: 'Invalid job post ID format' });
    }

    const applications = await Application.find({ jobPostId }).populate('userId', 'email name');
    if (!applications.length) {
      return res.status(404).json({ message: 'No applications found for this job post' });
    }

    const response = applications.map(app => ({
      user: app.userId,
      screeningAnswers: app.screeningAnswers,
      appliedAt: app.createdAt,
    }));

    res.json(response);
  } catch (err) {
    console.error('Admin fetch applications error:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
app.get('/api/company-logo/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;
    if (!mongoose.Types.ObjectId.isValid(fileId)) {
      console.warn('Invalid fileId format:', fileId);
      return res.status(400).json({ message: 'Invalid file ID format' });
    }
    const file = await gfs.find({ _id: new mongoose.Types.ObjectId(fileId) }).toArray();
    if (!file || file.length === 0) {
      console.warn('File not found in GridFS:', fileId);
      return res.status(404).json({ message: 'File not found' });
    }
    res.set('Content-Type', file[0].contentType);
    const downloadStream = gfs.openDownloadStream(new mongoose.Types.ObjectId(fileId));
    downloadStream.pipe(res);
    downloadStream.on('error', (err) => {
      console.error('Download stream error:', { message: err.message, stack: err.stack });
      res.status(500).json({ message: 'Error serving file' });
    });
  } catch (err) {
    console.error('Logo fetch error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

  // Get Profile
  app.get('/api/profile', authenticate, async (req, res) => {
    try {
      const user = await User.findById(req.userId).select(
        'name email phone state city houseNoStreet cvFileId companyName companyPhone companyLogo isAdmin'
      );
      if (!user) return res.status(404).json({ message: 'User not found' });
      console.log('Profile fetched:', user._id);
      res.json(user);
    } catch (err) {
      console.error('Get profile error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Get CV File
  app.get('/api/cv/:fileId', async (req, res) => {
    try {
      const fileId = req.params.fileId;
      if (!mongoose.Types.ObjectId.isValid(fileId)) {
        console.warn('Invalid fileId format:', fileId);
        return res.status(400).json({ message: 'Invalid file ID format' });
      }
      const file = await gfs.find({ _id: new mongoose.Types.ObjectId(fileId) }).toArray();

      if (!file || file.length === 0) {
        return res.status(404).json({ message: 'File not found' });
      }

      res.set('Content-Type', file[0].contentType);
      const downloadStream = gfs.openDownloadStream(new mongoose.Types.ObjectId(fileId));
      downloadStream.pipe(res);

      downloadStream.on('error', (err) => {
        console.error('Download stream error:', err);
        res.status(500).json({ message: 'Error serving file' });
      });
    } catch (err) {
      console.error('CV fetch error:', err);
      res.status(400).json({ message: 'Invalid file ID' });
    }
  });

  // Admin: Get Users with CVs
  app.get('/api/admin/users', authenticate, async (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
    try {
      const users = await User.find({ cvFileId: { $exists: true } })
        .select('name email phone state city houseNoStreet cvFileId');
      console.log('Fetched users with CVs, Count:', users.length);
      res.json(users);
    } catch (err) {
      console.error('Fetch users error:', err.message, err.stack);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Admin: Create Job Post
app.post('/api/admin/job-posts', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const { title, description, location, skills, screeningQuestions, workType } = req.body;
  console.log('Create job post request:', { userId: req.userId, title, location, skills, screeningQuestions, workType });

  const errors = {};
  if (!validateJobPost(title, description, location, workType)) {
    errors.jobPost = 'Title (3+ chars), description (10+ chars), location (2+ chars), and valid workType (Remote, Hybrid, Onsite) are required';
  }
  if (skills) {
    try {
      const parsedSkills = JSON.parse(skills);
      if (!Array.isArray(parsedSkills) || parsedSkills.some(s => !s || s.trim().length < 2)) {
        errors.skills = 'Skills must be an array of non-empty strings, each at least 2 characters';
      }
    } catch (err) {
      errors.skills = 'Invalid skills format; must be a JSON array of strings';
    }
  }
  if (screeningQuestions) {
    try {
      const parsedQuestions = JSON.parse(screeningQuestions);
      if (!Array.isArray(parsedQuestions) || parsedQuestions.length > 5) {
        errors.screeningQuestions = 'Screening questions must be an array with a maximum of 5 entries';
      } else if (parsedQuestions.some(q => !q || q.trim().length < 1)) {
        errors.screeningQuestions = 'Each screening question must be a non-empty string';
      }
    } catch (err) {
      errors.screeningQuestions = 'Invalid screening questions format; must be a JSON array of strings';
    }
  }

  if (Object.keys(errors).length > 0) {
    console.log('Validation errors:', errors);
    return res.status(400).json({ message: 'Validation failed', errors });
  }

  try {
    const user = await User.findById(req.userId);
    if (!user) {
      console.warn('User not found:', req.userId);
      return res.status(404).json({ message: 'User not found' });
    }
    if (!user.companyName || !user.companyLogo) {
      console.warn('Incomplete admin profile for job creation:', {
        userId: req.userId,
        companyName: !!user.companyName,
        companyLogo: !!user.companyLogo,
      });
      return res.status(400).json({ message: 'Please complete your company profile (name and logo) before creating a job post' });
    }

    const jobPost = new JobPost({
      title: title.trim(),
      description: description.trim(),
      location: location.trim(),
      postedBy: req.userId,
      isActive: true,
      skills: skills ? JSON.parse(skills) : [],
      screeningQuestions: screeningQuestions ? JSON.parse(screeningQuestions) : [],
      workType: workType.trim(), // Ensure workType is set
    });
    await jobPost.save();
    await jobPost.populate('postedBy', 'name email companyName companyLogo');
    console.log('Job post created:', { id: jobPost._id, skills: jobPost.skills, screeningQuestions: jobPost.screeningQuestions, workType: jobPost.workType });
    res.json({ message: 'Job post created successfully', jobPost });
  } catch (err) {
    console.error('Create job post error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

  // Admin: Get All Job Posts
app.get('/api/admin/job-posts', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  try {
    const jobPosts = await JobPost.find({ postedBy: req.userId })
      .populate('postedBy', 'name email companyName companyLogo')
      .lean();
    jobPosts.forEach((post) => {
      console.log('Job post:', {
        id: post._id,
        title: post.title,
        skills: post.skills || [],
        workType: post.workType || 'N/A', // Log workType
        screeningQuestions: post.screeningQuestions || [], // Log screeningQuestions
      });
      if (!post.postedBy) {
        console.warn(`Job post ${post._id} has no postedBy reference`);
      } else if (!post.postedBy.companyName) {
        console.warn(`Job post ${post._id} has postedBy user ${post.postedBy._id} with missing companyName`);
      }
    });
    console.log('Fetched job posts, Count:', jobPosts.length);
    res.json(jobPosts);
  } catch (err) {
    console.error('Fetch job posts error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

  // Admin: Get Single Job Post
  app.get('/api/admin/job-posts/:id', authenticate, async (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
    try {
      const jobPostId = req.params.id;
      if (!mongoose.Types.ObjectId.isValid(jobPostId)) {
        console.warn('Invalid jobPostId format:', jobPostId);
        return res.status(400).json({ message: 'Invalid job post ID format' });
      }
      const jobPost = await JobPost.findOne({ _id: jobPostId, postedBy: req.userId })
        .populate('postedBy', 'name email');
      if (!jobPost) return res.status(404).json({ message: 'Job post not found or you are not authorized' });
      console.log('Fetched job post:', jobPostId);
      res.json(jobPost);
    } catch (err) {
      console.error('Fetch job post error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Admin: Get Applications for a Job Post
// Admin: Get Applications for a Job Post

app.get('/api/admin/job-posts/:id/applications', authenticate, async (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  try {
    const jobPostId = req.params.id;
    if (!mongoose.Types.ObjectId.isValid(jobPostId)) {
      console.warn('Invalid jobPostId format:', jobPostId);
      return res.status(400).json({ message: 'Invalid job post ID format' });
    }
    const jobPost = await JobPost.findOne({ _id: jobPostId, postedBy: req.userId });
    if (!jobPost) return res.status(404).json({ message: 'Job post not found or you are not authorized to view its applications' });

    const applications = await Application.find({ jobPostId })
      .populate({
        path: 'userId',
        select: 'name email phone state city houseNoStreet cvFileId skills',
        model: 'User' // Explicitly specify the model
      })
      .populate('jobPostId', 'title')
      .lean();

    // Debug logging to verify populated data
    applications.forEach(app => {
      console.log('Application data:', {
        applicationId: app._id,
        userId: app.userId?._id,
        userEmail: app.userId?.email,
        skills: app.userId?.skills,
      });
    });

    // Transform response to ensure skills is always an array
    const transformedApplications = applications.map(app => ({
      ...app,
      userId: app.userId ? {
        ...app.userId,
        skills: Array.isArray(app.userId.skills) ? app.userId.skills : []
      } : null
    }));

    console.log('Fetched applications for job post:', jobPostId, 'Count:', transformedApplications.length);
    res.json(transformedApplications);
  } catch (err) {
    console.error('Fetch applications error:', {
      message: err.message,
      stack: err.stack
    });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

  // Resend OTP
  app.post('/api/resend-otp', async (req, res) => {
    const { email } = req.body;
    console.log('Resend OTP request:', { email });

    if (!validateEmail(email)) {
      console.warn('Invalid email format:', email);
      return res.status(400).json({ message: 'Invalid email format' });
    }

    try {
      const user = await User.findOne({ email: email.trim().toLowerCase() });
      if (!user) {
        console.warn('User not found:', email);
        return res.status(400).json({ message: 'User not found' });
      }
      if (user.verified) {
        console.warn('User already verified:', email);
        return res.status(400).json({ message: 'User already verified' });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      console.log('Generated new OTP:', otp);
      user.otp = otp;
      user.otpExpires = Date.now() + 10 * 60 * 1000;
      await user.save();

      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });

      console.log('Sending email to:', email);
      await transporter.sendMail({
        from: `"User Profile App" <${process.env.EMAIL_USER}>`,
        to: email.trim().toLowerCase(),
        subject: 'Your OTP Code',
        text: `Your new OTP code is ${otp}. It expires in 10 minutes.`,
      });
      console.log('Email sent successfully');

      res.json({ message: 'New OTP sent to email. Please verify.' });
    } catch (err) {
      console.error('Resend OTP error:', {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    console.log('Forgot password request (user):', { email });

    if (!validateEmail(email)) {
      console.warn('Invalid email format:', email);
      return res.status(400).json({ message: 'Invalid email format' });
    }

    try {
      const user = await User.findOne({ email: email.trim().toLowerCase() });
      if (!user) {
        console.warn('User not found:', email);
        return res.status(400).json({ message: 'User not found' });
      }
      if (user.isAdmin) {
        console.warn('Admin account attempted via user endpoint:', email);
        return res.status(403).json({ message: 'Admin accounts must use the admin forgot password endpoint' });
      }

      // Generate a reset token
      const resetToken = crypto.randomBytes(20).toString('hex');
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // Token expires in 1 hour
      await user.save();

      console.log('Reset token generated:', { userId: user._id, resetToken });

      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });

      const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
      console.log('Sending reset email to:', email, 'with URL:', resetUrl);

      await transporter.sendMail({
        from: `"Job Portal" <${process.env.EMAIL_USER}>`,
        to: email.trim().toLowerCase(),
        subject: 'Password Reset Request',
        text: `You are receiving this email because you (or someone else) requested a password reset for your account.\n\n` +
              `Please click the following link to reset your password:\n${resetUrl}\n\n` +
              `This link will expire in 1 hour. If you did not request a password reset, please ignore this email.\n`,
      });

      console.log('Reset email sent successfully');
      res.json({ message: 'Password reset email sent. Please check your inbox.' });
    } catch (err) {
      console.error('Forgot password error (user):', {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Reset Password Endpoint for Regular Users
  app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    console.log('Reset password request (user):', { token });

    if (!validatePassword(newPassword)) {
      console.warn('Invalid password format');
      return res.status(400).json({
        message: 'Password must be 8+ characters with uppercase, lowercase, number, and special character',
      });
    }

    try {
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });

      if (!user) {
        console.warn('Invalid or expired reset token:', token);
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }
      if (user.isAdmin) {
        console.warn('Admin account attempted via user endpoint:', user.email);
        return res.status(403).json({ message: 'Admin accounts must use the admin reset password endpoint' });
      }

      user.password = await bcrypt.hash(newPassword.trim(), 10);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      console.log('Password reset successful (user):', user._id);
      res.json({ message: 'Password reset successfully' });
    } catch (err) {
      console.error('Reset password error (user):', {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  app.post('/api/admin/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    console.log('Reset password request (admin):', { token });

    if (!validatePassword(newPassword)) {
      console.warn('Invalid password format');
      return res.status(400).json({
        message: 'Password must be 8+ characters with uppercase, lowercase, number, and special character',
      });
    }

    try {
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });

      if (!user) {
        console.warn('Invalid or expired reset token:', token);
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }
      if (!user.isAdmin) {
        console.warn('Non-admin account attempted via admin endpoint:', user.email);
        return res.status(403).json({ message: 'Not an admin account' });
      }

      user.password = await bcrypt.hash(newPassword.trim(), 10);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      console.log('Password reset successful (admin):', user._id);
      res.json({ message: 'Password reset successfully' });
    } catch (err) {
      console.error('Reset password error (admin):', {
        message: err.message,
        stack: err.stack,
      });
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });
  // Admin Forgot Password Endpoint
app.post('/api/admin/forgot-password', async (req, res) => {
  const { email } = req.body;
  console.log('Forgot password request (admin):', { email });

  if (!validateEmail(email)) {
    console.warn('Invalid email format:', email);
    return res.status(400).json({ message: 'Invalid email format' });
  }

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      console.warn('User not found:', email);
      return res.status(400).json({ message: 'User not found' });
    }
    if (!user.isAdmin) {
      console.warn('Non-admin account attempted via admin endpoint:', email);
      return res.status(403).json({ message: 'Not an admin account' });
    }

    // Generate a reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // Token expires in 1 hour
    await user.save();

    console.log('Reset token generated:', { userId: user._id, resetToken });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetUrl = `${process.env.FRONTEND_URL}/admin/reset-password/${resetToken}`;
    console.log('Sending reset email to:', email, 'with URL:', resetUrl);

    await transporter.sendMail({
      from: `"Job Portal" <${process.env.EMAIL_USER}>`,
      to: email.trim().toLowerCase(),
      subject: 'Admin Password Reset Request',
      text: `You are receiving this email because you (or someone else) requested a password reset for your admin account.\n\n` +
            `Please click the following link to reset your password:\n${resetUrl}\n\n` +
            `This link will expire in 1 hour. If you did not request a password reset, please ignore this email.\n`,
    });

    console.log('Reset email sent successfully');
    res.json({ message: 'Password reset email sent. Please check your inbox.' });
  } catch (err) {
    console.error('Forgot password error (admin):', {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
  // User: Get All Job Posts
app.get('/api/jobs', async (req, res) => {
  try {
    const apiUrl = process.env.API_URL || 'https://jobportal-back-1jtg.onrender.com';

    if (!process.env.API_URL) {
      console.warn('API_URL is not defined in environment variables, using fallback:', apiUrl);
    }
    const jobPosts = await JobPost.find({ isActive: true })
      .select('title description location createdAt postedBy skills workType screeningQuestions') // Add workType and screeningQuestions
      .populate({
        path: 'postedBy',
        select: 'companyName companyLogo',
      })
      .lean();
    const jobsWithCompany = jobPosts.map(job => ({
      _id: job._id,
      title: job.title,
      description: job.description,
      location: job.location,
      createdAt: job.createdAt,
      skills: Array.isArray(job.skills) ? job.skills : [],
      workType: job.workType || 'Remote', // Fallback to 'Remote' if missing
      screeningQuestions: Array.isArray(job.screeningQuestions) ? job.screeningQuestions : [], // Ensure array
      company: {
        name: job.postedBy?.companyName || 'Unknown Company',
        logo: job.postedBy?.companyLogo && mongoose.Types.ObjectId.isValid(job.postedBy.companyLogo)
          ? `${apiUrl}/api/company-logo/${job.postedBy.companyLogo}`
          : null,
      },
    }));
    console.log('Fetched job posts for users:', jobsWithCompany.length);
    res.json(jobsWithCompany);
  } catch (err) {
    console.error('Fetch jobs error:', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
  // User: Get Applied Job Posts
 app.get('/api/user/applications', authenticate, async (req, res) => {
  try {
    const applications = await Application.find({ userId: req.userId })
      .populate({
        path: 'jobPostId',
        select: 'title description location',
        match: { isActive: true }, // Only include applications for active job posts
      })
      .lean();
    // Filter out applications where jobPostId is null (i.e., job post doesn't exist or isn't active)
    const validApplications = applications.filter(app => app.jobPostId !== null);
    console.log('Fetched user applications:', req.userId, 'Count:', validApplications.length);
    res.json(validApplications);
  } catch (err) {
    console.error('Fetch user applications error:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});
} catch (err) {
  console.error('Error during route initialization:', {
    message: err.message,
    stack: err.stack,
  });
  process.exit(1);
}

// Catch-all route
app.use((req, res) => {
  console.warn('Unmatched route:', {
    method: req.method,
    url: req.url,
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers,
  });
  res.status(404).json({ message: 'Route not found' });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Global error:', {
    message: err.message,
    stack: err.stack,
    method: req.method || 'N/A',
    url: req.url || 'N/A',
    origin: req.get('Origin') || 'no-origin',
    headers: req.headers || {},
  });
  res.status(500).json({ message: 'Server error', error: err.message });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Export for Vercel
module.exports = app;
