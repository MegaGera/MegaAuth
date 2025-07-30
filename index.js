import './config/loadEnv.js';
import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';

import { UserRepository } from './UserRepository.js';
import { extractJwtPayload } from './config/userConfig.js';

const app = express();

app.set('view engine', 'ejs');

app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

// Add CORS middleware to allow all subdomains and the root domain of megagera.com only in production
if (process.env.NODE_ENV === 'production') {
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, false); // block non-browser requests
      const megageraRegex = /^https:\/\/(.*\.)?megagera\.com$/;
      if (megageraRegex.test(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  }));
}

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

const validateAdmin = (req, res, next) => {
  validateJWT(req, res, () => {
    if (req.body.data.permissions.some(p => p.type === 'admin')) {
      next();
    } else {
      return res.status(403).json({ error: 'Forbidden' });
    }
  });
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

app.get('/users', validateAdmin, async (req, res) => {
  try {
    const users = await UserRepository.findAll();
    return res.render('users', { users });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load users' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await UserRepository.login({ username, password });
    const token = jwt.sign(
      extractJwtPayload(user),
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

app.post('/login/test', async (req, res) => {
  try {
    const user = await UserRepository.findRandomTestUser();
    const token = jwt.sign(
      extractJwtPayload(user),
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

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password, email } = req.body;

  // Check if username and password are provided
  if (!username || username.trim() === '' || !password || password.trim() === '') {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Only admins can register users without email
  if (!email || email.trim() === '') {
    return validateAdmin(req, res, async () => {
      try {
        const id = await UserRepository.create({ username, password, email: undefined });
        return res.send({ id });
      } catch (error) {
        return res.status(400).json({ error: error.message });
      }
    });
  }

  // Public registration (email required)
  if (!email || email.trim() === '') {
    return res.status(400).json({ error: 'Email is required' });
  }

  UserRepository.create({ username, password, email })
    .then(id => res.send({ id }))
    .catch(error => res.status(400).json({ error: error.message }));
});

app.post('/create-test-user', validateAdmin, async (req, res) => {
  try {
    const testUsername = `test-user-${Date.now()}`;
    const testPassword = `test-${Date.now()}`;
    const id = await UserRepository.create({
      username: testUsername,
      password: testPassword,
      email: '',
      test: true
    });
    return res.send({ id, username: testUsername, password: testPassword });
  } catch (error) {
    console.error('Create test user error:', error);
    return res.status(400).json({ error: error.message });
  }
});

app.post('/delete', validateAdmin, async (req, res) => {
  const { username } = req.body;
  try {
    const id = await UserRepository.delete({ username });
    return res.send({ id });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.patch('/permissions', validateAdmin, async (req, res) => {
  const { username, permissions, action } = req.body;
  try {
    const id = await UserRepository.updatePermissions({ username, permissions, action });
    return res.send({ id });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.post('/change-password', validateJWT, async (req, res) => {
  const { oldPassword } = req.body;
  const { newPassword } = req.body;
  const { username } = req.body.data;
  try {
    const id = await UserRepository.changePassword({ username, oldPassword, newPassword });
    return res.send({ id });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.post('/reset-password', validateAdmin, async (req, res) => {
  const { username } = req.body;
  try {
    const id = await UserRepository.resetPassword({ username });
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
  return res.status(200).json({ message: 'Validated', data: req.body.data });
});

app.get('/validate/admin', validateAdmin, (req, res) => {
  return res.status(200).json({ message: 'Validated as Admin' });
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

app.get('/validate/megamedia', validateJWT, (req, res) => {
  if (req.body.data.permissions.some(p => p.name === 'megamedia')) {
    return res.status(200).json({ message: 'Validated' });
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

const PORT = process.env.PORT || 3150;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
