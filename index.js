const express = require('express');
const axios = require('axios');
require('dotenv').config();


const app = express();
const PORT = process.env.PORT;


app.use(express.json());

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

// Verificar el token JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token inválido' });
    }
    req.user = decoded;
    next();
  });
};

//Genera Token
const generateToken = (user) => {
  return jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
};


// Ruta para el login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const response = await axios.post('http://localhost:6002/login', {
      username,
      password
    });

    const { token } = response.data;
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Credenciales incorrectas' });
  }
});



app.get('/registros', verifyToken, async (req, res) => {
  try {
    const response = await axios.get('http://localhost:6001/all_registers', {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });
    const registros = response.data;
    res.json({ registros });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener los registros' });
  }
});

//Ruta para crear nuevos usuarios
app.put('/usuarios', verifyToken, async (req, res) => {
  try {
    const { username, password, nombre, apellido } = req.body;

    if (!username || !password || !nombre || !apellido) {
      return res.status(400).json({ error: 'Por favor, proporcione todos los campos requeridos' });
    }

    const response = await axios.put('http://localhost:6002/usuarios', req.body, {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });
    const usuarios = response.data;
    res.json({ usuarios });
  } catch (error) {
    console.error(error.response);
    if (error.response.status == 403) {
      res.status(403).json(error.response.data);
    }
    console.error('Error al hacer la solicitud al microservicio:', error.message);
    res.status(500).json({ error: 'Error al enviar los datos al microservicio de usuarios' });
  }
});

// Ruta para ver los usuarios guardados
app.get('/usuarios', verifyToken, async (req, res) => {
  try {
    const response = await axios.get('http://localhost:6002/usuariosguardados', {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });
    const usuarios = response.data;
    res.json({ usuarios });
  } catch (error) {
    console.error(error.response);
    if (error.response.status == 403) {
      res.status(403).json(error.response.data);
    }
    console.error('Error al hacer la solicitud al microservicio:', error.message);
    res.status(500).json({ error: 'Error al obtener los usuarios' });
  }
});

// Ruta para asignar roles a los usuarios
app.put('/usuarios/:id/roles', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { roles } = req.body;

    if (!roles || !Array.isArray(roles)) {
      return res.status(400).json({ error: 'Por favor, proporcione una lista de roles válida' });
    }

    const response = await axios.put(`http://localhost:6003/usuarios/${id}/roles`, { roles }, {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });

    const usuarios = response.data;
    res.json({ usuarios });
  } catch (error) {
    console.error(error.response);
    if (error.response.status == 403) {
      res.status(403).json(error.response.data);
    }
    console.error('Error al hacer la solicitud al microservicio:', error.message);
    res.status(500).json({ error: 'Error al asignar roles al usuario' });
  }
});

// Ruta para suspender un usuario
app.put('/suspendUser', verifyToken, async (req, res) => {
  const { userId } = req.body;

  try {
    //const token = req.headers.authorization.split(' ')[1]; // Obtener el token del encabezado Authorization
    console.log(req.headers.authorization)
    const response = await axios.put('http://localhost:6004/suspendUser', {
      userId
    }, {
      headers: {
        Authorization: req.headers.authorization
      }
    });

    const { message, suspendedUser } = response.data;
    res.json({ message, suspendedUser });
  } catch (error) {
    console.log(error.response)
    if (error.response.status == 403) {
      res.status(403).json(error.response.data);
    }
    console.error('Error al hacer la solicitud al microservicio:', error.message);
    res.status(500).json({ error: 'Error al suspensión del usuario' });
  }
});

// Ruta para levantar la suspensión de un usuario
app.put('/unsuspendUser', verifyToken, async (req, res) => {
  const { userId } = req.body;

  try {
    const response = await axios.put('http://localhost:6004/unsuspendUser', {  // Cambiado a axios.put y la URL corregida
      userId
    }, {
      headers: {
        Authorization: req.headers.authorization // Pasar el token en la cabecera
      }
    });

    const { message, unsuspendedUser } = response.data;
    res.json({ message, unsuspendedUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al levantar la suspensión del usuario' });
  }
});

//Ruta para levantar la api
app.get('/marcas/:marca/:year', async (req, res) => {
  try {
    const { marca, year } = req.params;

    const response = await axios.get(`http://localhost:${process.env.PORT6}/marcas/${marca}/${year}`);
    const trims = response.data.trims;
    
    const autos = trims.map(trim => {
      return {
        marca: trim.make_display,
        modelo: trim.model_name,
        año: trim.model_year
      };
    });
    res.json({ autos });
  } catch (error) {
    console.error('Error al obtener modelos de autos:', error);
    res.status(500).json({ error: 'Error al obtener modelos de autos' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
