const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const axios = require('axios');


const app = express();
const PORT6 = process.env.PORT6;

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

app.get('/marcas/:marca/:year', async (req, res) => {
  try {
    const { marca, year } = req.params;
    const response = await axios.get(`https://www.carqueryapi.com/api/0.3/?cmd=getTrims&make=${marca}&year=${year}`);
    const trims = response.data.Trims;
    res.json({ trims });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener los modelos de autos' });
  }
});

app.listen(PORT6, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT6}`);
});
