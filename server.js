require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt'); // Or const bcrypt = require('bcryptjs'); if you installed bcryptjs
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("MongoDB connected"));

console.log('Loaded MONGO_URI:', process.env.MONGO_URI);

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'movies'
  })
}));

// User Schema
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, unique: true },
  password: String
}));

// Middleware to protect routes
function requireLogin(req, res, next) {
  if (!req.session.userId) {return res.redirect('/login');}
  next();
}

// Serve public files
app.use(express.static(path.join(__dirname, 'public')));
// Protect access to movie-details.html
app.get('/movie-details', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/movie-details.html'));
});

// Protect access to movie-nav.html
app.get('/movie-nav', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/movie-nav.html'));
});

// Signup
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/signup.html'));
});
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
    return res.redirect('/login');
  } catch (err) {
    console.error(err);
    return res.send("<script>alert('Error creating user'); window.location.href = '/signup';</script>");
  }
});



// Login
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user._id;
    return res.redirect('/');
  }
  res.send('Invalid credentials');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Protected route
app.get('/', (req, res) => {
  res.redirect('/signup');
});


const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}/signup`));
