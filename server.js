require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));

// ✅ Log .env values for debugging
console.log("MONGO_URI:", process.env.MONGO_URI);
console.log("SESSION_SECRET:", process.env.SESSION_SECRET);

// ✅ MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ✅ Express-session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions'
  })
}));

// ✅ Debug session middleware
app.use((req, res, next) => {
  console.log("Session userId:", req.session.userId);
  next();
});

// ✅ User model
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
}));

// ✅ Login protection middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// ✅ Serve public assets
app.use(express.static(path.join(__dirname, 'public')));

// ✅ Home route: show only if logged in
app.get('/', (req, res) => {
  console.log("Accessed / with session:", req.session.userId);
  if (req.session.userId) {
    return res.sendFile(path.join(__dirname, 'public/index.html'));
  }
  res.redirect('/signup');
});

// ✅ Signup page
app.get('/signup', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'views/signup.html'));
});

// ✅ Handle signup
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.send("<script>alert('All fields are required'); window.location.href = '/signup';</script>");
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.send("<script>alert('User already exists. Please log in.'); window.location.href = '/login';</script>");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ email, password: hashedPassword });
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.send("<script>alert('Error creating user'); window.location.href = '/signup';</script>");
  }
});

// ✅ Login page
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

// ✅ Handle login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user._id;
    req.session.save(() => {
      console.log("✅ Session saved for user:", req.session.userId);
      res.redirect('/');
    });
  } else {
    res.send("<script>alert('Invalid credentials'); window.location.href = '/login';</script>");
  }
});

// ✅ Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ✅ Protected movie pages
app.get('/movie-details', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/movie-details.html'));
});

app.get('/movie-nav', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/movie-nav.html'));
});

// ✅ Catch-all fallback
app.use((req, res) => {
  res.status(404).send("404: Page not found.");
});

// ✅ Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
