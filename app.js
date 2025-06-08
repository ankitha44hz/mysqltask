const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./config/db');
const auth = require('./middleware/auth');
const redis = require('redis');
require('dotenv').config();

const redisClient = redis.createClient();

redisClient.on('error', err => {
  console.error('Redis error:', err);
});

redisClient.connect().then(() => console.log('Connected to Redis'));

const app = express();
app.use(express.json());

// Register
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'Please provide username and password' });

  const hashedPassword = bcrypt.hashSync(password, 8);

  const user = { username, password: hashedPassword };

  db.query('INSERT INTO users SET ?', user, (err) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    res.status(201).json({ message: 'User registered successfully' });
  });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'Please provide username and password' });

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = results[0];
    const isValid = bcrypt.compareSync(password, user.password);

    if (!isValid) return res.status(401).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ token });
  });
});

// Get tasks 
app.get('/tasks', auth, async (req, res) => {
  const cacheKey = `tasks:${req.user.id}`;

  try {
    const cached = await redisClient.get(cacheKey);

    if (cached) {
      console.log('Cache hit');
      return res.json(JSON.parse(cached));
    }

    db.query('SELECT * FROM tasks WHERE user_id = ?', [req.user.id], async (err, results) => {
      if (err) return res.status(500).json({ message: 'Database error', error: err });

      await redisClient.set(cacheKey, JSON.stringify(results)); 
      console.log('Cache miss. Data cached.');
      res.json(results);
    });
  } catch (err) {
    console.error('Redis error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create task
app.post('/tasks', auth, (req, res) => {
  const { name, description, status } = req.body;
  if (!name) return res.status(400).json({ message: 'Task name is required' });

  const task = {
    name,
    description: description || '',
    status: status || 'pending',
    user_id: req.user.id,
  };

  db.query('INSERT INTO tasks SET ?', task, async (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });

    await redisClient.del(`tasks:${req.user.id}`);
    res.status(201).json({ message: 'Task created', taskId: result.insertId });
  });
});

// Update task
app.put('/tasks/:id', auth, (req, res) => {
  const { name, description, status } = req.body;
  const taskId = req.params.id;

  db.query(
    'UPDATE tasks SET name = ?, description = ?, status = ? WHERE id = ? AND user_id = ?',
    [name, description, status, taskId, req.user.id],
    async (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error', error: err });
      if (result.affectedRows === 0)
        return res.status(404).json({ message: 'Task not found or not yours' });

      await redisClient.del(`tasks:${req.user.id}`);
      res.json({ message: 'Task updated' });
    }
  );
});

// Delete task
app.delete('/tasks/:id', auth, (req, res) => {
  const taskId = req.params.id;

  db.query('DELETE FROM tasks WHERE id = ? AND user_id = ?', [taskId, req.user.id], async (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (result.affectedRows === 0)
      return res.status(404).json({ message: 'Task not found or not yours' });

    await redisClient.del(`tasks:${req.user.id}`);
    res.json({ message: 'Task deleted' });
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));