const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./config/db');
const auth = require('./middleware/auth');
require('dotenv').config();

const app = express();
app.use(express.json());

// User Registration
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'Please provide username and password' });

  const hashedPassword = bcrypt.hashSync(password, 8);

  const user = { username, password: hashedPassword };

  db.query('INSERT INTO users SET ?', user, (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    res.status(201).json({ message: 'User registered successfully' });
  });
});

// User Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'Please provide username and password' });

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = results[0];
    const passwordIsValid = bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) return res.status(401).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ token });
  });
});

// Get all tasks
app.get('/tasks', auth, (req, res) => {
  db.query('SELECT * FROM tasks WHERE user_id = ?', [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    res.json(results);
  });
});

// Create a new task 
app.post('/tasks', auth, (req, res) => {
  const { name, description, status } = req.body;
  if (!name) return res.status(400).json({ message: 'Task name is required' });

  const task = {
    name,
    description: description || '',
    status: status || 'pending',
    user_id: req.user.id,
  };

  db.query('INSERT INTO tasks SET ?', task, (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    res.status(201).json({ message: 'Task created', taskId: result.insertId });
  });
});

//task updation 
app.put('/tasks/:id', auth, (req, res) => {
  const taskId = req.params.id;
  const { name, description, status } = req.body;

  db.query(
    'UPDATE tasks SET name = ?, description = ?, status = ? WHERE id = ? AND user_id = ?',
    [name, description, status, taskId, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error', error: err });
      if (result.affectedRows === 0)
        return res.status(404).json({ message: 'Task not found or not yours' });
      res.json({ message: 'Task updated' });
    }
  );
});

// Delete task
app.delete('/tasks/:id', auth, (req, res) => {
  const taskId = req.params.id;

  db.query('DELETE FROM tasks WHERE id = ? AND user_id = ?', [taskId, req.user.id], (err, result) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (result.affectedRows === 0)
      return res.status(404).json({ message: 'Task not found or not yours' });
    res.json({ message: 'Task deleted' });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
