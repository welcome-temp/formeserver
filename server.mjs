import express from 'express';
import session from 'express-session';
import passport from 'passport';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import MongoStore from 'connect-mongo';
import cors from 'cors';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as TwitterStrategy } from 'passport-twitter';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import bodyParser from 'body-parser';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import http from 'http';
import { Server } from 'socket.io';
import sharedSession from 'express-socket.io-session';

dotenv.config();
const app = express();
const PORT = process.env.SERVER;
const FRONTEND_ORIGIN = process.env.BASE_SERVER;
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: FRONTEND_ORIGIN,
    methods: ['GET', 'POST'],
    credentials: true
  }
});

const sessionMiddleware = session({
  secret: process.env.MY_CODE,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: { maxAge: 12 * 60 * 1000, secure: false }
});

// ===== Middleware =====
app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// Share session with Socket.IO
io.use(sharedSession(sessionMiddleware, {
  autoSave: true
}));

// ===== MongoDB Connection =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));



// Cloudinary config
cloudinary.config({ 
  cloud_name:process.env.CLOUD_NAME, 
  api_key:process.env.API_KEY,
  api_secret:process.env.API_SECRET });

// Cloudinary storage for multer 
const storage = new CloudinaryStorage({ 
  cloudinary: cloudinary, params: { 
    folder: 'properties', allowed_formats: ['jpg', 'png', 'jpeg'],
    transformation: [{ width: 1000, height: 750, crop: "limit" }] }, });

const upload = multer({ storage });


// ===== Schemas =====
const pendingUserSchema = new mongoose.Schema({
  email: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: String,
  token: String,
  createdAt: { type: Date, default: Date.now, expires: 1200 } // 20 minutes
});
const PendingUser = mongoose.model("PendingUser", pendingUserSchema);

const userSchema = new mongoose.Schema({
  provider: String,
  providerId: String,
  email: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: String,
  role: { type: String, default: "user" },
  resetToken: String,
  resetTokenExpiry: Date,

  fullname: { type: String, required: false }, 
  gender: { type: String, enum: ['male', 'female', 'other'], required: false }, 
  age: { type: Number, required: false }, 
  date: { type: String, required: false },
  location: { type: String, required: false }, 
  origin: { type: String, required: false }, 
  occupation: { type: String, required: false },
  education: { type: String, enum: ['high_school', 'bachelor', 'master', 'doctorate'], default: 'bachelor', required: false },
  religion: { type: String, required: false },
  preferredGender: { type: String, enum: ['male', 'female', 'other', 'no_preference'], required: false }, // Gender preference
  preferredAgeRange: {
    min: { type: Number, required: false }, 
    max: { type: Number, required: false }, 
  },
  lookingFor: { type: String, enum: ['friendship', 'dating', 'long-term', 'no_preference'], required: false }, 
  profileComplete: { type: Boolean, default: false }, 
  smoking: { type: String, required: false },
  drinking: { type: String, required: false },
  petPreference: { type: String, required: false },
  hobbies: { type: String, required: false },
  bio: { type: String, required: false },
  profile: { type: String, required: false }, 
  
});
const User = mongoose.model("User", userSchema);



// ===== Passport Strategies =====
passport.use(new GoogleStrategy({
  clientID: process.env.MY_GOOGLE_ID,
  clientSecret: process.env.MY_GOOGLE_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  const email = profile.emails?.[0]?.value || '';
  const username = email.split('@')[0];

  let user = await User.findOne({ provider: 'google', providerId: profile.id });
  const existingUser = await User.findOne({ email });

  // If a user exists with that email but is not using Google as a provider
  if (existingUser && (existingUser.provider !== 'google' || existingUser.providerId !== profile.id)) {
    return done(null, false, { message: "You already signed up with this email. Please login normally." });
  }
  if (!user) {
    user = await User.create({ provider: 'google', providerId: profile.id, email, username });
  }
  return done(null, user);
}));

passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_CLIENT,
  consumerSecret: process.env.TWITTER_SECRET,
  callbackURL: "/auth/twitter/callback",
  includeEmail: true
}, async (token, tokenSecret, profile, done) => {
  const email = profile.emails?.[0]?.value || '';
  const username = profile.username || email.split('@')[0];

  let user = await User.findOne({ provider: 'twitter', providerId: profile.id });
  if (!user) {
    user = await User.create({ provider: 'twitter', providerId: profile.id, email, username });
  }
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));


passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) return done(null, false, { message: 'Incorrect email or password.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return done(null, false, { message: 'Incorrect email or password.' });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ===== Auth Routes =====

// Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
    // This covers both cases: wrong provider or other errors
    return res.redirect(`${FRONTEND_ORIGIN}/authentication/err?message=${encodeURIComponent(info?.message || 'Google login failed')}`);
  }
    req.logIn(user, (err) => {
      if (err) return next(err);
      const redirectTo = req.session.returnTo || '/';
      delete req.session.returnTo;
      res.redirect(`${FRONTEND_ORIGIN}${redirectTo}`);
    });
  })(req, res, next);
});

// Twitter OAuth
app.get('/auth/twitter', passport.authenticate('twitter'));

app.get('/auth/twitter/callback',
  passport.authenticate('twitter', { failureRedirect: '/' }),
  (req, res) => {
    const redirectTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(`${FRONTEND_ORIGIN}${redirectTo}`);
  }
);

// ===== Email/Password Signup =====
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const errors = {};

      // Check if email already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ success: false, errors: { email: "Email already exists" } });
  }

  // Check if username already exists
  const existingUsername = await User.findOne({ username });
  if (existingUsername) {
    return res.status(400).json({ success: false, errors: { username: "That Username is already taken" } });
  }


    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ success: false, errors });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString("hex");

    await PendingUser.create({ username, email, password: hashedPassword, token });
    
    const verificationLink = `${process.env.BACKEND_DOMAIN}/verify-email?token=${token}`;
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      tls: { rejectUnauthorized: false }
    });

    try {
    await transporter.sendMail({
      from: "Wetpool",
      to: email,
      subject: "Verify Your Email",
      html: `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Email Verification Code</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      background: #f2f4f6;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .email-wrapper {
      width: 100%;
      padding: 20px;
      box-sizing: border-box;
      background: #f2f4f6;
    }
    .email-content {
      max-width: 600px;
      margin: 0 auto;
      background: #ffffff;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    }
    .email-header {
      text-align: center;
      padding: 20px 0;
      background-color:#7A0C2E ;
    }
    .email-header img {
      height: 40px;
    }
    .email-body {
      padding: 30px 20px;
      text-align: center;
    }
    .email-body h2 {
      margin: 0 0 10px;
      color: #333;
    }
    .email-body p {
      font-size: 16px;
      color: #555;
      margin-bottom: 30px;
    }
    .verification-code {
      display: inline-block;
      font-size: 24px;
      font-weight: bold;
      letter-spacing: 2px;
      background: #eef3fc;
      padding: 10px 20px;
      border-radius: 6px;
      color: #7A0C2E;
      margin-bottom: 20px;
      text-decoration:none;
    }
    .email-footer {
      padding: 20px;
      text-align: center;
      font-size: 12px;
      color: #999;
      background: #f8f8f8;
    }
    @media only screen and (max-width: 600px) {
      .email-body {
        padding: 20px 10px;
      }
    }
  </style>
</head>
<body>
  <div class="email-wrapper">
    <div class="email-content">
      <div class="email-header">
        <img src="https://grande-spot.onrender.com/works/assets/images/Logo.png" alt="Logo" />
      </div>
      <div class="email-body">
        <h2>Email Verification</h2>
        <p> You just got 1 inch closer to your date,verify your email to join the pool</p>
        <a href="${verificationLink}"class="verification-code">Verify Email</a>
        <p>This is valid for 20 minutes. If you didn’t request this, please ignore this email.</p>
      </div>
      <div class="email-footer">
        © 2025 <a style="color:red;">  Wetpool</a>. All rights reserved.<br>
        hotline +1 443421566 <br> Contact: wetpool920@gmail.com
      </div>
    </div>
  </div>
</body>
</html>`
    });
      } catch (emailError) {
  console.error("Email sending failed:", emailError);
  return res.status(500).json({ success: false, error: "Failed to send verification email" });
}

    return res.json({ success: true, message: "Verification email sent. Please check your inbox." });

  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ success: false, error: "Server error during signup" });
  }
});

// ===== Email Verification =====
app.get("/verify-email", async (req, res) => {
  try {
    const { token } = req.query;
    const pendingUser = await PendingUser.findOne({ token });

    if (!pendingUser) return res.status(400).send("Invalid or expired token.");

    const { username, email, password } = pendingUser;
    const newUser = await User.create({ username, email, password, role: "user" });

    await PendingUser.deleteOne({ _id: pendingUser._id });

    
    req.login(newUser, (err) => {
  if (err) return res.status(500).send("Session login error after verification");

  const redirectTo = req.session.returnTo || '/';
  delete req.session.returnTo;
  res.redirect(`${FRONTEND_ORIGIN}${redirectTo}`);
});

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error during verification");
  }
});

 // ===== Login Route =====
app.post('/login', (req, res, next) => {
  const { email, password } = req.body;

  // Check if it's an admin login
  const isAdmin1 = email === process.env.ADMIN_LOGIN1 && password === process.env.ADMIN_PASSWORD1;
  const isAdmin2 = email === process.env.ADMIN_LOGIN2 && password === process.env.ADMIN_PASSWORD2;

  if (isAdmin1 || isAdmin2) {
    // Manually create session for admin
    req.session.userId = crypto.randomUUID();
    req.session.role = 'admin';
    req.session.cookie.maxAge = 24 * 60 * 60 * 1000;

    return req.session.save((err) => {
      if (err) return res.status(500).json({ success: false, error: 'Admin session error' });

      return res.json({
        success: true,
        message: 'Welcome Admin',
        role: 'admin',
        redirectTo: req.session.returnTo || null,
      });
    });
  }

  // Otherwise, use Passport for normal users
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ success: false, error: info.message });

    req.logIn(user, (err) => {
      if (err) return next(err);

      const redirectPath = req.session.returnTo || null;
      if (redirectPath) delete req.session.returnTo;

      return res.json({
        success: true,
        message: 'Login successful',
        role: user.role,
        redirectTo: redirectPath,
      });
    });
  })(req, res, next);
});



// ===== Session Check =====
app.get('/session', (req, res) => {
  if (!req.isAuthenticated()) {
    const requestedPath = req.headers['x-request-path'];
    if (requestedPath && requestedPath !== '/authentication/signin') {
      req.session.returnTo = requestedPath;
      console.log('Session expired, storing returnTo:', req.session.returnTo);
    }
    return res.status(401).json({ user: null });
  }

  // Extract only necessary user info and include profileComplete
  const { _id, username, email, role, profileComplete } = req.user;

  res.json({
    user: {
      _id,
      username,
      email,
      role,
      profileComplete: profileComplete || false,
    }
  });
});

// ===== Logout =====
app.post('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) {
      return res.status(500).json({ message: 'Logout error', error: err });
    }
    res.status(200).json({ message: 'Logged out successfully' });
  });
});


// === users info session ===
app.post('/getinfo', upload.single('profile'), async (req, res) => {
  try {
    
        const userId = req.session.passport?.user?._id;
if (!userId) {
  console.log('No session userId found.');
  return res.status(401).json({ message: 'Unauthorized' });
}
    
    // Check if users info already exists
  const existinginfo = await User.findById(userId);
if (existinginfo && existinginfo.profileComplete) {
  console.log('User info already exists');
  return res.status(401).json({ message: 'You are already registered please login' });
  res.redirect('/');
  return
}

    console.log('--- Incoming /getinfo Request ---');
    console.log('Session:', req.session);
    console.log('Body:', req.body);
    console.log('Uploaded File:', req.file);

    const {
      fullname,
      gender,
      age,
      date,
      location,
      origin,
      occupation,
      education,
      religion,
      preferredGender,
      preferredAgeRange,
      lookingFor,
      smoking,
      drinking,
      petPreference,
      hobbies,
      bio,
    } = req.body;
    
      
    const profile = req.file?.path;

    const update = {
      fullname,
      gender,
      age,
      date,
      location,
      origin,
      occupation,
      education,
      religion,
      preferredGender,
      lookingFor,
      smoking,
      drinking,
      petPreference: typeof petPreference === 'object' ? petPreference.join(',') : petPreference,
      hobbies: typeof hobbies === 'object' ? hobbies.join(',') : hobbies,
      bio,
      profile,
      profileComplete: true
    };

    if (preferredAgeRange && preferredAgeRange.includes('-')) {
      const [min, max] = preferredAgeRange.split('-').map(Number);
      update.preferredAgeRange = { min, max };
    }

    console.log('Final Update Object:', update);

    const updatedUser = await User.findByIdAndUpdate(userId, update, { new: true });

    res.status(200).json({ message: 'Profile updated', data: updatedUser });
  } catch (err) {
    console.error('Error updating user info:', err.stack || err);
    res.status(500).json({ message: 'Error saving info', error: err.message });
  }
});


app.get('/profile', async (req, res) => {
  const userId = req.session.passport?.user?._id;
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const user = await User.findOne({ _id: userId, profileComplete: true })
      .select('-password -__v')
      .lean();

    if (!user) {
      return res.status(403).json({ message: 'Profile is not complete or user not found' });
    }

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch profile' });
  }
});

// all users route
app.get('/users', async (req, res) => {
  try {
    const users = await User.find({ profileComplete: true }) // filter only completed profiles
      .select('-password -__v')
      .lean();

    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

app.get('/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching user' });
  }
});


// Message Schema
const messageSchema = new mongoose.Schema({
  from: String,
  to: String,
  content: String,
  timestamp: { type: Date, default: Date.now },
  delivered: { type: Boolean, default: false },
  read: { type: Boolean, default: false }
});
const Message = mongoose.model('Message', messageSchema);

app.get('/messages/:user1/:user2', async (req, res) => {
  const { user1, user2 } = req.params;
  const messages = await Message.find({
    $or: [
      { from: user1, to: user2 },
      { from: user2, to: user1 },
    ],
  }).sort({ timestamp: 1 });
  res.json(messages);
});

app.post('/messages/mark-as-read', async (req, res) => {
  const { from, to } = req.body;

  try {
    await Message.updateMany(
      { from, to, read: false },
      { $set: { read: true } }
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error marking messages as read:", err);
    res.status(500).json({ error: 'Failed to mark messages as read' });
  }
});


// ===== Socket.IO Handling =====
const userSocketMap = {};

io.on('connection', async (socket) => {
  const session = socket.handshake.session;
  if (!session?.passport?.user) {
    console.log('[SOCKET] No session found in handshake');
    return;
  }
  const userId = session.passport.user;
  const user = await User.findById(userId);
  if (!user) {
    console.log('[SOCKET] User not found for session');
    return;
  }
  const username = user.username;
  userSocketMap[username] = socket.id;
  console.log(`[SOCKET CONNECT] ${username} connected as socket ${socket.id}`);

  // Deliver undelivered messages
  try {
    const undelivered = await Message.find({ to: username, delivered: false });
    for (const msg of undelivered) {
      socket.emit('receiveMessage', msg);
      msg.delivered = true;
      await msg.save();
      console.log(`[SOCKET] Delivered undelivered message from ${msg.from} to ${username}`);
    }
  } catch (err) {
    console.error('[SOCKET ERROR] While delivering undelivered messages:', err);
  }

  // Incoming messages
  socket.on('send_message', async ({ to, content }) => {
    const from = username;
    const timestamp = new Date();

    const message = new Message({ from, to, content, timestamp });

    try {
      await message.save();
      const recipientSocketId = userSocketMap[to];
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('receive_message', message);
        message.delivered = true;
        await message.save();
        console.log(`[SOCKET] Sent message from ${from} to ${to}`);
      } else {
        console.log(`[SOCKET] ${to} is offline, stored for later`);
      }
    } catch (err) {
      console.error('[SOCKET ERROR] While sending/storing message:', err);
    }
  });
  
  socket.on('markAsRead', async ({ from, to }) => {
  try {
    await Message.updateMany(
      { from, to, read: false },
      { $set: { read: true } }
    );
    console.log(`[READ] Marked messages from ${from} to ${to} as read`);
  } catch (err) {
    console.error('[SOCKET ERROR] While marking messages as read:', err);
  }
});

  socket.on('disconnect', () => {
    delete userSocketMap[username];
    console.log(`[SOCKET DISCONNECT] ${username} disconnected`);
  });
});
//end of message wares 


// ===== Start Server =====
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT} 😘🎉`);
});
