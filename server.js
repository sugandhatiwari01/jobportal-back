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

const app = express();

paypal.configure({
  mode: 'sandbox', // Change to 'live' for production
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
    if (!origin || origin === 'http://localhost:5173' || /\.vercel\.app$/.test(origin)||'https://jobportal-front-beta.vercel.app') {
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
  otp: { type: String },
  otpExpires: { type: Date },
  verified: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  subscription: { type: mongoose.Schema.Types.ObjectId, ref: 'Subscription' },
});
const User = mongoose.model('User', userSchema);

// Job Post Schema
const jobPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  location: { type: String, required: true },
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
});
const JobPost = mongoose.model('JobPost', jobPostSchema);

// Application Schema
const applicationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  jobPostId: { type: mongoose.Schema.Types.ObjectId, ref: 'JobPost', required: true },
  appliedAt: { type: Date, default: Date.now },
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
    console.error('Auth error:', err.message);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes
try {
  // Get Current Subscription
  app.get('/api/subscription/current', authenticate, async (req, res) => {
    try {
      const subscription = await Subscription.findOne({ userId: req.userId });
      if (!subscription) {
        return res.status(404).json({ message: 'No subscription found' });
      }
      res.json({ plan: subscription.plan });
    } catch (err) {
      console.error('Fetch current subscription error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Create or Update Subscription
  app.post('/api/subscription/checkout', authenticate, async (req, res) => {
    const { plan } = req.body;
    console.log('Subscription checkout request:', { userId: req.userId, plan });

    // Validate plan
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

      if (plan === 'free') {
        // Handle free plan
        let subscription = await Subscription.findOne({ userId: req.userId });
        if (subscription) {
          // Update existing subscription
          subscription.plan = 'free';
          subscription.applicantLimit = subscriptionPlans.free.applicantLimit;
          subscription.paypalPaymentId = null;
          await subscription.save();
        } else {
          // Create new subscription
          subscription = new Subscription({
            userId: req.userId,
            plan: 'free',
            applicantLimit: subscriptionPlans.free.applicantLimit,
            paypalPaymentId: null,
          });
          await subscription.save();
          user.subscription = subscription._id;
        }
        user.isAdmin = true;
        await user.save();

        console.log('Free plan activated:', { userId: req.userId, subscriptionId: subscription._id });
        return res.json({ message: 'Free plan activated successfully' });
      }

      // Handle paid plans
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
      res.status(500).json({ message: 'Server error', error: err.message });
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
        // Update existing subscription
        subscription.plan = plan;
        subscription.applicantLimit = subscriptionPlans[plan].applicantLimit;
        subscription.paypalPaymentId = paymentId;
        await subscription.save();
      } else {
        // Create new subscription
        subscription = new Subscription({
          userId: req.userId,
          plan,
          applicantLimit: subscriptionPlans[plan].applicantLimit,
          paypalPaymentId: paymentId,
        });
        await subscription.save();
        user.subscription = subscription._id;
      }
      user.isAdmin = true;
      await user.save();

      console.log('Subscription activated:', { userId: req.userId, plan, subscriptionId: subscription._id });
      res.json({ message: 'Subscription activated successfully', plan });
    } catch (err) {
      console.error('Subscription verify error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Admin: Switch User Subscription
  app.put('/api/admin/subscription/:userId', authenticate, async (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
    const { userId } = req.params;
    const { plan } = req.body;
    console.log('Switch subscription request:', { adminId: req.userId, userId, plan });

    try {
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        console.warn('Invalid userId format:', userId);
        return res.status(400).json({ message: 'Invalid user ID format' });
      }
      if (!subscriptionPlans[plan]) {
        console.warn('Invalid plan:', plan);
        return res.status(400).json({ message: 'Invalid plan selected' });
      }

      const user = await User.findById(userId);
      if (!user) {
        console.warn('User not found:', userId);
        return res.status(404).json({ message: 'User not found' });
      }

      let subscription = await Subscription.findOne({ userId });
      if (!subscription) {
        console.warn('No subscription found for user:', userId);
        return res.status(400).json({ message: 'User has no active subscription' });
      }

      subscription.plan = plan;
      subscription.applicantLimit = subscriptionPlans[plan].applicantLimit;
      subscription.paypalPaymentId = plan === 'free' ? null : `ADMIN_UPDATED_${Date.now()}`;
      await subscription.save();

      user.isAdmin = true;
      await user.save();

      console.log('Subscription switched:', { userId, plan });
      res.json({ message: 'Subscription switched successfully', plan });
    } catch (err) {
      console.error('Switch subscription error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Job Application Endpoint
  app.post('/api/jobs/apply/:id', authenticate, async (req, res) => {
    const jobPostId = req.params.id;
    console.log('Job apply request:', { userId: req.userId, jobPostId });

    try {
      if (!mongoose.Types.ObjectId.isValid(jobPostId)) {
        console.warn('Invalid jobPostId format:', jobPostId);
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
        console.log('User already applied:', req.userId, jobPostId);
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
        console.log('Job post deactivated due to applicant limit:', jobPostId);
        return res.status(400).json({ message: 'Applicant limit reached for this job post' });
      }

      const application = new Application({
        userId: req.userId,
        jobPostId,
      });
      await application.save();

      const newApplicationCount = await Application.countDocuments({ jobPostId });
      if (newApplicationCount >= subscription.applicantLimit) {
        jobPost.isActive = false;
        await jobPost.save();
        console.log('Job post deactivated after application:', jobPostId);
      }

      console.log('Application submitted:', application._id);
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
        isAdmin: req.body.isAdmin || false,
      });
      console.log('Saving user:', { name: user.name, email: user.email, state: user.state, city: user.city });
      await user.save();
      console.log('User saved:', user._id);

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
      if (!user) return res.status(400).json({ message: 'Invalid email or password' });
      if (!user.verified) return res.status(400).json({ message: 'Email not verified' });

      const isMatch = await bcrypt.compare(password.trim(), user.password);
      if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

      const token = jwt.sign(
        { userId: user._id, isAdmin: user.isAdmin },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      console.log('Login successful:', user._id);
      res.json({ token, isAdmin: user.isAdmin });
    } catch (err) {
      console.error('Login error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Profile Update with CV Upload
  app.post('/api/profile', authenticate, upload.single('cv'), async (req, res) => {
    const { phone, state, city, houseNoStreet } = req.body;
    const cv = req.file;
    console.log('Profile update request:', { userId: req.userId, phone, state, city, houseNoStreet, file: !!cv });

    const errors = {};
    if (!validatePhone(phone)) errors.phone = 'Phone must be a 10-digit number';
    if (!validateState(state)) errors.state = 'Invalid state';
    if (!validateCity(city)) errors.city = 'City must be at least 2 characters';
    if (!validateHouseNoStreet(houseNoStreet)) errors.houseNoStreet = 'Address must be at least 5 characters if provided';
    if (!cv) errors.cv = 'CV file is required';

    if (Object.keys(errors).length > 0) {
      console.log('Validation errors:', errors);
      return res.status(400).json({ message: 'Validation failed', errors });
    }

    try {
      const user = await User.findById(req.userId);
      if (!user) return res.status(404).json({ message: 'User not found' });

      if (user.cvFileId) {
        try {
          await gfs.delete(new mongoose.Types.ObjectId(user.cvFileId));
          console.log('Deleted old CV:', user.cvFileId);
        } catch (err) {
          console.error('Error deleting old CV:', err.message);
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
      console.log('Profile updated:', user._id);
      res.json({ message: 'Profile updated successfully', fileId });
    } catch (err) {
      console.error('Profile update error:', err.message, err.stack);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Get Profile
  app.get('/api/profile', authenticate, async (req, res) => {
    try {
      const user = await User.findById(req.userId).select('name email phone state city houseNoStreet cvFileId');
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
    const { title, description, location } = req.body;
    console.log('Create job post request:', { title, location });

    const errors = {};
    if (!validateJobPost(title, description, location)) {
      errors.jobPost = 'Title (3+ chars), description (10+ chars), and location (2+ chars) are required';
    }

    if (Object.keys(errors).length > 0) {
      console.log('Validation errors:', errors);
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
      console.log('Job post created:', jobPost._id);
      res.json({ message: 'Job post created successfully', jobPost });
    } catch (err) {
      console.error('Create job post error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // Admin: Get All Job Posts
  app.get('/api/admin/job-posts', authenticate, async (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
    try {
      const jobPosts = await JobPost.find({ postedBy: req.userId })
        .populate('postedBy', 'name email');
      console.log('Fetched job posts, Count:', jobPosts.length);
      res.json(jobPosts);
    } catch (err) {
      console.error('Fetch job posts error:', err.message);
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
        .populate('userId', 'name email phone state city houseNoStreet cvFileId')
        .populate('jobPostId', 'title');
      console.log('Fetched applications for job post:', jobPostId, 'Count:', applications.length);
      res.json(applications);
    } catch (err) {
      console.error('Fetch applications error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // User: Get All Job Posts
  app.get('/api/jobs', async (req, res) => {
    try {
      const jobPosts = await JobPost.find({ isActive: true }).select('title description location createdAt');
      console.log('Fetched job posts for users:', jobPosts.length);
      res.json(jobPosts);
    } catch (err) {
      console.error('Fetch jobs error:', err.message);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  });

  // User: Get Applied Job Posts
  app.get('/api/user/applications', authenticate, async (req, res) => {
    try {
      const applications = await Application.find({ userId: req.userId })
        .populate('jobPostId', 'title description location');
      console.log('Fetched user applications:', req.userId, 'Count:', applications.length);
      res.json(applications);
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
