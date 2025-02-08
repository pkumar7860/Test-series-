const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = 5000;

// Middleware
app.use(express.json());
app.use(cors());

// Database Connection
mongoose.connect('mongodb://localhost:27017/blogDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String
});
const User = mongoose.model('User', userSchema);

// Blog Schema
const blogSchema = new mongoose.Schema({
    title: String,
    content: String,
    author: String,
    createdAt: { type: Date, default: Date.now }
});
const Blog = mongoose.model('Blog', blogSchema);

// Comment Schema
const commentSchema = new mongoose.Schema({
    postId: mongoose.Schema.Types.ObjectId,
    username: String,
    comment: String,
    createdAt: { type: Date, default: Date.now }
});
const Comment = mongoose.model('Comment', commentSchema);

// Register Route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    
    res.json({ message: "User registered successfully!" });
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, username: user.username });
});

// Fetch All Blogs
app.get('/blogs', async (req, res) => {
    const blogs = await Blog.find().sort({ createdAt: -1 });
    res.json(blogs);
});

// Fetch Single Blog Post
app.get('/blogs/:id', async (req, res) => {
    const blog = await Blog.findById(req.params.id);
    res.json(blog);
});

// Create New Blog Post
app.post('/blogs', async (req, res) => {
    const { title, content, author } = req.body;
    const newBlog = new Blog({ title, content, author });
    
    await newBlog.save();
    res.json({ message: "Blog created successfully!" });
});

// Add Comment
app.post('/comments', async (req, res) => {
    const { postId, username, comment } = req.body;
    const newComment = new Comment({ postId, username, comment });
    
    await newComment.save();
    res.json({ message: "Comment added successfully!" });
});

// Get Comments for a Blog Post
app.get('/comments/:postId', async (req, res) => {
    const comments = await Comment.find({ postId: req.params.postId }).sort({ createdAt: -1 });
    res.json(comments);
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = 5000;

// Middleware
app.use(express.json());
app.use(cors());

// Secret Key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Verify Token Middleware
const authenticateUser = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: "Access Denied" });

    jwt.verify(token.split(' ')[1], JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid Token" });
        req.user = user;
        next();
    });
};

// Comment Schema
const commentSchema = new mongoose.Schema({
    postId: mongoose.Schema.Types.ObjectId,
    username: String,
    comment: String,
    createdAt: { type: Date, default: Date.now }
});
const Comment = mongoose.model('Comment', commentSchema);

// Add Comment (Requires Authentication)
app.post('/comments', authenticateUser, async (req, res) => {
    const { postId, comment } = req.body;
    const username = req.user.username; // Extracted from JWT

    if (!comment) return res.status(400).json({ message: "Comment cannot be empty" });

    const newComment = new Comment({ postId, username, comment });
    await newComment.save();

    res.json({ message: "Comment added successfully!" });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// Database Connection
mongoose.connect('mongodb://localhost:27017/blogDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    resetToken: String,
    resetTokenExpiration: Date
});
const User = mongoose.model('User', userSchema);

// Nodemailer Setup (Use a real email service in production)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your-email@gmail.com',
        pass: 'your-email-password'
    }
});

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken = token;
    user.resetTokenExpiration = Date.now() + 3600000; // 1-hour expiry
    await user.save();

    const resetLink = `http://localhost:5000/reset-password?token=${token}`;
    await transporter.sendMail({
        to: email,
        subject: "Password Reset",
        text: `Click here to reset your password: ${resetLink}`
    });

    res.json({ message: "Password reset link sent to email" });
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();

    res.json({ message: "Password reset successful!" });
});

// Start Server
app.listen(5000, () => console.log("Server running on http://localhost:5000"));
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

mongoose.connect('mongodb://localhost:27017/blogDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
    googleId: String,
    username: String,
    email: String
});
const User = mongoose.model('User', userSchema);

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ googleId: profile.id });

    if (!user) {
        user = new User({
            googleId: profile.id,
            username: profile.displayName,
            email: profile.emails[0].value
        });
        await user.save();
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    done(null, { token, username: user.username });
}));

// Google Auth Route
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    res.redirect(`http://localhost:5500/?token=${req.user.token}&username=${req.user.username}`);
});

// Start Server
app.listen(5000, () => console.log("Server running on http://localhost:5000"));
const params = new URLSearchParams(window.location.search);
const token = params.get('token');
const username = params.get('username');

if (token) {
    localStorage.setItem('token', token);
    localStorage.setItem('username', username);
    window.location.href = 'index.html';
}
