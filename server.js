const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const cookieParser = require('cookie-parser');


const app = express();
const port = process.env.PORT || 3000;


app.use(cookieParser());

// Middleware
app.use(cors({
  origin: 'http://localhost:5000', 
  credentials: true
}));
app.use(bodyParser.json());

// Database Connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});


// Improved database connection logging
pool.connect()
 .then(() => {
   console.log('✅ Successfully connected to PostgreSQL database');
   console.log(`Database: ${pool.options.database}`);
   console.log(`Host: ${pool.options.host}`);
 })
 .catch((err) => {
   console.error('❌ Database connection error:', err.message);
   console.error('Connection Details:');
   console.error(`User: ${pool.options.user}`);
   console.error(`Host: ${pool.options.host}`);
   console.error(`Database: ${pool.options.database}`);
 });

// Alternative error handling in connection
process.on('unhandledRejection', (reason, promise) => {
 console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Middleware for JWT Authentication
const authenticateToken = (req, res, next) => {
  const token = req.cookies.jwt; // Use cookie instead of Authorization header

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};


app.get('/validate-session', authenticateToken, (req, res) => {
  res.json({ valid: true });
});

// Protected Routes
app.get('/students', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM students');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error retrieving students' });
  }
});

app.post('/students', authenticateToken, async (req, res) => {
  const { name, age, gender, country, university } = req.body;

  if (!name || !age || !gender || !country || !university) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const query = `
      INSERT INTO students (name, age, gender, country, university)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `;

    const result = await pool.query(query, [name, age, gender, country, university]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Database error' });
  }
});


// Delete a student by ID (Protected Route)
app.delete('/students/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM students WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Student not found' });
    }
    
    res.status(200).json({ message: 'Student deleted successfully' });
  } catch (error) {
    console.error('Error deleting student:', error);
    res.status(500).json({ message: 'Error deleting student' });
  }
});


app.put('/students/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, age, gender, country, university } = req.body;
 
  // Validate input
  if (!name || !age || !gender || !country || !university) {
    return res.status(400).json({ message: 'All fields are required' });
  }
 
  try {
    const result = await pool.query(
      'UPDATE students SET name = $1, age = $2, gender = $3, country = $4, university = $5 WHERE id = $6 RETURNING *',
      [name, age, gender, country, university, id]
    );
 
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Student not found' });
    }
 
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating student:', error);
    res.status(500).json({ message: 'Error updating student' });
  }
 });

// Registration Route with Email Validation
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Basic email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  try {
    // Check if email already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const query = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email';
    const result = await pool.query(query, [name, email, hashedPassword]);
    
    const newUser = result.rows[0];
    res.status(201).json({
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
    });
  } catch (error) {
    res.status(500).json({ message: 'Registration failed' });
  }
});


app.post('/login', async (req, res) => {
  console.log('Server: Login request body:', req.body);
  const { email, password } = req.body;

  try {
    console.log('Server: Attempting to find user with email:', email);
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    console.log('Server: Database query result:', result.rows);
    const user = result.rows[0];

    if (!user) {
      console.log('Server: No user found');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    console.log('Server: Comparing  ');
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      console.log('Server: Password invalid');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    console.log('Server: Generating token');
    const token = jwt.sign(
      { id: user.id, email: user.email }, 
      process.env.JWT_SECRET || 'fallback_secret', 
      { expiresIn: '1h' }
    );

    console.log('Server: Setting JWT cookie');
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 3600000 
    });
  
    console.log('Server: Login successful');
    res.json({ 
      message: 'Login successful',
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (error) {
    console.error('Server: Detailed login error:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
});


app.post('/logout', (req, res) => {
  res.clearCookie('jwt');
  res.json({ message: 'Logged out successfully' });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});