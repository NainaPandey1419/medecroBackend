require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const connectDB = require('./config/db');
const User = require('./models/User');

const app = express();
app.use(express.json());
app.use(cors());

connectDB();

const authRoutes = require('./routes/Auth');

app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({
    message: "Welcome to the API",
    version: "1.0.0",
    endpoints: {
      auth: {
        register: "/api/register",
        login: "/api/login"
      },
      dashboard: "/api/dashboard"
    },
   
  });
});

const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, 'mySecretKey1234');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Token is not valid' });
  }
};

app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  
  const user = new User({
    username,
    password: await bcrypt.hash(password, 10),
    role
  });

  await user.save();
  res.json({ message: 'User registered successfully' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id, role: user.role }, 'mySecretKey1234', { expiresIn: '1h' });
  res.json({ token, role: user.role });
});

app.get('/api/dashboard', auth, (req, res) => {
  if (req.user.role === 'Admin') {
    res.json({ message: 'Welcome to the Admin Dashboard', data: 'Admin specific data' });
  } else {
    res.json({ message: 'Welcome to the User Dashboard', data: 'User specific data' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));