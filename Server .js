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
