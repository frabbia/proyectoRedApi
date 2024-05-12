const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT4 = process.env.PORT4;

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

(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS roles (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(50) UNIQUE NOT NULL
      )
    `);

    await client.query(`INSERT INTO roles (nombre) VALUES ('Admin') ON CONFLICT (nombre) DO NOTHING`);
    await client.query(`INSERT INTO roles (nombre) VALUES ('Encargado') ON CONFLICT (nombre) DO NOTHING`);
    await client.query(`INSERT INTO roles (nombre) VALUES ('Regular') ON CONFLICT (nombre) DO NOTHING`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios_roles (
        usuario_id INT,
        rol_id INT,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
        FOREIGN KEY (rol_id) REFERENCES roles(id)
      )
    `);
  } catch (err) {
    console.error('Error creando las tablas', err);
  } finally {
    client.release();
  }
})();

//Ver roles 
app.get('/roles', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM roles');
    client.release();
    const roles = result.rows;
    res.json({ roles });
  } catch (error) {
    console.error('Error al obtener los roles', error);
    res.status(500).json({ error: 'Error al obtener los roles' });
  }
});

//Asignacion de roles
app.put('/usuarios/:id/roles', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { roles } = req.body;

    if (!roles || !Array.isArray(roles)) {
      return res.status(400).json({ error: 'Por favor, proporcione una lista de roles válida' });
    }

    const client = await pool.connect();

   
    await client.query('UPDATE usuarios SET role_id = $1 WHERE id = $2', [roles[0], id]); //Actualiza la tabla usuario columna de roles_id

    client.release();

    res.json({ message: 'Roles asignados correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al asignar roles al usuario' });
  }
});


app.listen(PORT4, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT4}`);
});
