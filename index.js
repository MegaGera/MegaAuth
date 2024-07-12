import './config/loadEnv.js';
import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

import { UserRepository } from './UserRepository.js';

const app = express();

app.set('view engine', 'ejs');

app.use(express.json());
app.use(cookieParser());

const validateJWT = (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const data = jwt.verify(token, process.env.SECRET_JWT_KEY);
    req.body = { ...req.body, data };
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

app.get('/', async (req, res) => {
  const token = req.cookies.access_token;
  if (!token) return res.render('login');
  try {
    const data = jwt.verify(token, process.env.SECRET_JWT_KEY);
    const users = await UserRepository.findAll();
    return res.render('admin', { data, users });
  } catch (error) {
    return res.render('login');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await UserRepository.login({ username, password });
    const token = jwt.sign(
      { id: user._id, username: user.username, permissions: user.permissions },
      process.env.SECRET_JWT_KEY,
      { expiresIn: '1h' });
    return res
      .cookie(
        'access_token',
        token,
        {
          httpOnly: true,
          domain: process.env.NODE_ENV === 'production' ? '.megagera.com' : '',
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 1000 * 60 * 60
        })
      .send({ user, token });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.post('/register', validateJWT, async (req, res) => {
  const { username, password } = req.body;
  try {
    const id = await UserRepository.create({ username, password });
    return res.send({ id });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.post('/delete', validateJWT, async (req, res) => {
  const { username } = req.body;
  try {
    const id = await UserRepository.delete({ username });
    return res.send({ id });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.patch('/permissions', validateJWT, async (req, res) => {
  const { username, permissions, action } = req.body;
  try {
    const id = await UserRepository.updatePermissions({ username, permissions, action });
    return res.send({ id });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.post('/logout', (req, res) => {
  return res
    .clearCookie('access_token'
      , { domain: process.env.NODE_ENV === 'production' ? '.megagera.com' : '' }
    )
    .json({ message: 'Logged out' });
});

app.get('/validate', validateJWT, (req, res) => {
  return res.status(200).json({ message: 'Validated' });
});

app.get('/validate/megagoal', validateJWT, (req, res) => {
  if (req.body.data.permissions.some(p => p.name === 'megagoal')) {
    return res.status(200).json({ message: 'Validated', data: req.body.data });
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

app.get('/validate/megadocu', validateJWT, (req, res) => {
  if (req.body.data.permissions.some(p => p.name === 'megadocu')) {
    return res.status(200).json({ message: 'Validated' });
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

const PORT = process.env.PORT || 3150;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
