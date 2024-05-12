const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT5 = process.env.PORT5;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});


app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

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
      
      if (decoded.estado == false) { // False es deshabilitado
     
        return res.status(403).json({ error: 'Acceso denegado. Usuario deshabilitado' });
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


// Endpoint para suspender un usuario
app.put('/suspendUser', verifyToken, async (req, res) => {


  const { userId } = req.body;

  try {
    const client = await pool.connect();

    const userExistQuery = await client.query('SELECT * FROM usuarios WHERE id = $1', [userId]);
    if (userExistQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const suspendUserQuery = await client.query('UPDATE usuarios SET estado = false WHERE id = $1 RETURNING *', [userId]);
    const suspendedUser = suspendUserQuery.rows[0];

    client.release();

    res.json({ message: 'Usuario suspendido exitosamente', suspendedUser });
  } catch (error) {
    console.error('Error al suspender usuario:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint para levantar la suspensión de un usuario
app.put('/unsuspendUser', verifyToken, async (req, res) => {
  const { userId } = req.body;

  try {
    const client = await pool.connect();

    const userExistQuery = await client.query('SELECT * FROM usuarios WHERE id = $1', [userId]);
    if (userExistQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const unsuspendUserQuery = await client.query('UPDATE usuarios SET estado = true WHERE id = $1 RETURNING *', [userId]);
    const unsuspendedUser = unsuspendUserQuery.rows[0];

    client.release();

    res.json({ message: 'Suspensión de usuario levantada exitosamente', unsuspendedUser });
  } catch (error) {
    console.error('Error al levantar la suspensión de usuario:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.listen(PORT5, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT5}`);
});
