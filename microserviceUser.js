const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();


const app = express();
const PORT = process.env.PORT3;


const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

const connectDB = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL NOT NULL,
        username varchar(50) NOT NULL,
        pass varchar(100) NOT NULL,
        nombre varchar(100) NOT NULL,
        apellido varchar(100) NOT NULL,
        estado boolean NOT NULL,
        role_id INT,
        PRIMARY KEY(id)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS usuarios_username_key ON usuarios USING btree ("username");
    `);
    console.log('Tabla de usuarios creada correctamente');
  } catch (err) {
    console.error('Error creando la tabla', err);
  } finally {
    client.release();
  }
};

connectDB();

//Middleware para verificar el token JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token inválido' });
    }
    //Permiso para el admin
    const client = await pool.connect();
    try {

      console.log(decoded)

      if (decoded.role != 1) { // Verifica si el rol es 1, corresponde al admin

        return res.status(403).json({ error: 'Acceso denegado. Se requiere el rol de Admin' });
      }

      req.user = decoded;

      next();
    } catch (error) {
      console.error('Error al verificar el rol del usuario:', error);
      res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
      client.release();
    }
  });
};

const generateToken = (user) => {
  
  return jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
};

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM usuarios WHERE username = $1', [username]);
    const user = result.rows[0];
    client.release();

    if (!user) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const validPassword = await bcrypt.compare(password, user.pass);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = generateToken({ username: user.username,role: user.role_id, estado: user.estado  }); 

    res.json({ token }); 
  } catch (error) {
    console.error('Error en la autenticación', error);
    res.status(500).json({ error: 'Error en la autenticación' });
  }
});

//Crear nuevos usuarios
app.put('/usuarios', verifyToken, async (req, res) => {
  const { username, password, nombre, apellido } = req.body;

  if (!username || !password || !nombre || !apellido) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const client = await pool.connect();
    
    const result = await client.query('SELECT id FROM roles WHERE nombre = $1', ['Regular']);
    const role_id = result.rows[0].id; 

    const newUserResult = await client.query('INSERT INTO usuarios (username, pass, nombre, apellido, estado, role_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [username, hashedPassword, nombre, apellido, true, role_id]);
    
    client.release();
    const newUser = newUserResult.rows[0];

    res.json(newUser);
  } catch (error) {
    console.error('Error al registrar el usuario', error);
    res.status(500).json({ error: 'Error al registrar el usuario' });
  }
});

//Ver usuarios guardados
app.get('/usuariosguardados', verifyToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM usuarios');
    client.release();
    const usuarios = result.rows;
    res.json({ usuarios });
  } catch (error) {
    console.error('Error al obtener los usuarios', error);
    res.status(500).json({ error: 'Error al obtener los usuarios' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
