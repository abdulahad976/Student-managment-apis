const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const cors = require('cors');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();



const app = express();
const port = 3000;


// Middleware
app.use(cors());
app.use(bodyParser.json());

const pool = new Pool({
    user: 'postgres',           
    host: 'localhost',          
    database: 'students',    
    password: '1122',           
    port: 5432,                
  });

pool.connect((err) => {
  if (err) {
    console.error('Database connection error', err.stack);
  } else {
    console.log('Connected to PostgreSQL');
  }
});

// Routes

// Get all students
app.get('/students', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM students');
    res.json(result.rows);
  } catch (error) {
    console.error('Error retrieving students:', error);
    res.status(500).send('Error retrieving students');
  }
});

// Add a new student
app.post('/students', async (req, res) => {
    const { name, age, gender, country, university } = req.body;
  
    // Check if all required fields are present
    if (!name || !age || !gender || !country || !university) {
      return res.status(400).send('All fields are required');
    }
  
    try {
      const query = `
        INSERT INTO students (name, age, gender, country, university)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *;
      `;
  
      const values = [name, age, gender, country, university];
      const result = await pool.query(query, values);
  
      res.status(201).send(result.rows[0]);
    } catch (err) {
      console.error('Error adding student:', err.message);
      res.status(500).send('Database error');
    }
  });
  

app.put('/students/:id', async (req, res) => {
  const { id } = req.params;
  const { name, age, gender, country, university } = req.body;

  try {
    const result = await pool.query(
      'UPDATE students SET name = $1, age = $2, gender= $3, country = $4, university = $5 WHERE id = $6 RETURNING *',
      [name, age, gender, country, university, id]
    );
    if (result.rowCount === 0) {
      res.status(404).send('Student not found');
    } else {
      res.json(result.rows[0]);
    }
  } catch (error) {
    console.error('Error updating student:', error);
    res.status(500).send('Error updating student');
  }
});

// Delete a student by ID
app.delete('/students/:id', async (req, res) => {
    const { id } = req.params;
  
    try {
      const result = await pool.query('DELETE FROM students WHERE id = $1', [id]);
      if (result.rowCount === 0) {
        res.status(404).json({ message: 'Student not found' });
      } else {
        res.status(200).json({ message: 'Student deleted successfully' });
      }
    } catch (error) {
      console.error('Error deleting student:', error);
      res.status(500).json({ message: 'Error deleting student' });
    }
  });
  





// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET;

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
  
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Insert user into the database
    const query = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email';
    const values = [name, email, hashedPassword];
  
    try {
      const result = await pool.query(query, values);  
      const newUser = result.rows[0];
      res.status(201).json({
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
      });
    } catch (error) {
      console.error('Error registering user:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  // Login Route
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    // Find the user by email
    const query = 'SELECT * FROM users WHERE email = $1';
    try {
      const result = await pool.query(query, [email]);  // Use pool.query
      const user = result.rows[0];
  
      if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }
  
      // Compare password with the hashed password stored in the database
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }
  
      // Create JWT token
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  
      res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
      console.error('Error logging in user:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });






app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
