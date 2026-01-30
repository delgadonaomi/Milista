const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Pool de conexiones a Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Para Neon
  }
});

// Verificar conexión
pool.on('connect', () => {
  console.log('✅ Conectado a Neon PostgreSQL');
});

// Middleware de autenticación
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// RUTAS DE AUTENTICACIÓN

// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Faltan campos' });
    }

    // Verificar si usuario existe
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email ya registrado' });
    }

    // Hash de contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );

    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ user: result.rows[0], token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(400).json({ error: 'Contraseña incorrecta' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ 
      user: { id: user.id, name: user.name, email: user.email }, 
      token 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// RUTAS DE LISTAS

// Obtener todas las listas del usuario
app.get('/api/lists', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM lists WHERE user_id = $1 ORDER BY priority = $2, created_at DESC',
      [req.user.id, 'alta']
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Crear lista
app.post('/api/lists', verifyToken, async (req, res) => {
  try {
    const { title, priority } = req.body;
    
    if (!title) {
      return res.status(400).json({ error: 'Título requerido' });
    }

    const result = await pool.query(
      'INSERT INTO lists (user_id, title, priority) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, title, priority || 'media']
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar lista
app.put('/api/lists/:id', verifyToken, async (req, res) => {
  try {
    const { title, priority, is_favorite } = req.body;
    const { id } = req.params;

    const result = await pool.query(
      'UPDATE lists SET title = COALESCE($1, title), priority = COALESCE($2, priority), is_favorite = COALESCE($3, is_favorite) WHERE id = $4 AND user_id = $5 RETURNING *',
      [title, priority, is_favorite, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Lista no encontrada' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar lista
app.delete('/api/lists/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Eliminar tareas de la lista primero
    await pool.query('DELETE FROM tasks WHERE list_id = $1', [id]);

    // Eliminar lista
    const result = await pool.query(
      'DELETE FROM lists WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Lista no encontrada' });
    }

    res.json({ message: 'Lista eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// RUTAS DE TAREAS

// Obtener tareas de una lista
app.get('/api/lists/:id/tasks', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT t.* FROM tasks t JOIN lists l ON t.list_id = l.id WHERE l.id = $1 AND l.user_id = $2',
      [id, req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Crear tarea
app.post('/api/lists/:id/tasks', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { text, priority } = req.body;

    if (!text) {
      return res.status(400).json({ error: 'Texto requerido' });
    }

    const result = await pool.query(
      'INSERT INTO tasks (list_id, text, priority, done) VALUES ($1, $2, $3, false) RETURNING *',
      [id, text, priority || 'media']
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar tarea
app.put('/api/tasks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { text, priority, done } = req.body;

    const result = await pool.query(
      'UPDATE tasks SET text = COALESCE($1, text), priority = COALESCE($2, priority), done = COALESCE($3, done) WHERE id = $4 RETURNING *',
      [text, priority, done, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Tarea no encontrada' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar tarea
app.delete('/api/tasks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM tasks WHERE id = $1 RETURNING *', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Tarea no encontrada' });
    }

    res.json({ message: 'Tarea eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Test
app.get('/api/health', (req, res) => {
  res.json({ status: 'Backend funcionando ✅' });
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${port}`);
});
