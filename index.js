import './config/loadEnv.js';
import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

import { UserRepository } from './UserRepository.js';
import { extractJwtPayload } from './config/userConfig.js';
import { connectRabbitMQ } from './config/rabbitmq.js';
import {
  logUserLogin,
  logUserRegister,
  logTestUserCreated,
  logPasswordChange,
  logPasswordReset
} from './services/authLogger.js';

const app = express();

// Connect to RabbitMQ for logging
connectRabbitMQ();

app.set('view engine', 'ejs');

app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: true, // Changed to true to save sessions even if not modified
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const { id, emails } = profile;
    const email = emails[0].value;

    // Create or find user with needsUsername flag
    const user = await UserRepository.createOrFindGoogleUser({
      googleId: id,
      email,
      name: email.split('@')[0], // Use email prefix as name
      needsUsername: true // Always require username selection for new users
    });

    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user._id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await UserRepository.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

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

    // Log the login action
    await logUserLogin(username, 'normal', req);

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

    // Log the test login action
    await logUserLogin(user.username, 'test', req);

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

        // Log admin-created user registration
        await logUserRegister(username, req);

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
    .then(async (id) => {
      // Log public user registration
      await logUserRegister(username, req);
      res.send({ id });
    })
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

    // Log test user creation (admin action)
    await logTestUserCreated(req.body.data.username, testUsername, req);

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

    await logPasswordChange(username, req);

    return res.send({ id });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.post('/reset-password', validateAdmin, async (req, res) => {
  const { username } = req.body;
  try {
    const id = await UserRepository.resetPassword({ username });

    await logPasswordReset(req.body.data.username, username, req);

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
  return res.status(200).json({ message: 'Validated as Admin', data: req.body.data });
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

// Google OAuth Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  async (req, res) => {
    try {
      const user = req.user;

      // Check if user needs to set username
      if (user.needsUsername || user.username.startsWith('temp_')) {
        // Store user in session and redirect to username selection
        req.session.googleUser = user;
        req.session.save((err) => {
          if (err) {
            console.error('Session save error:', err);
            return res.redirect('/login?error=session_failed');
          }
          res.redirect('/username-selection');
        });
        return;
      }

      // User already has username, proceed with login
      const token = jwt.sign(
        extractJwtPayload(user),
        process.env.SECRET_JWT_KEY,
        { expiresIn: '1h' }
      );

      await logUserLogin(user.username, 'google', req);

      res
        .cookie(
          'access_token',
          token,
          {
            httpOnly: true,
            domain: process.env.NODE_ENV === 'production' ? '.megagera.com' : '',
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 1000 * 60 * 60
          }
        )
        .redirect('/');
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      res.redirect('/login?error=oauth_failed');
    }
  }
);

// Username selection page
app.get('/username-selection', (req, res) => {
  if (!req.session.googleUser) {
    return res.redirect('/login');
  }
  res.render('username-selection');
});

// Check username availability
app.post('/auth/google/check-username', async (req, res) => {
  const { username } = req.body;
  try {
    const isAvailable = await UserRepository.checkUsernameAvailability({ username });
    res.json({ available: isAvailable });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Complete username setup
app.post('/auth/google/complete', async (req, res) => {
  const { username } = req.body;

  console.log('Session data:', req.session);
  console.log('Google user in session:', req.session.googleUser);

  if (!req.session.googleUser) {
    console.error('No Google user session found');
    return res.status(400).json({ error: 'No Google user session found' });
  }

  try {
    const user = await UserRepository.completeGoogleUserSetup({
      googleId: req.session.googleUser.googleId,
      username
    });

    const token = jwt.sign(
      extractJwtPayload(user),
      process.env.SECRET_JWT_KEY,
      { expiresIn: '1h' }
    );

    await logUserLogin(user.username, 'google', req);

    // Clear the session
    req.session.googleUser = null;
    req.session.save((err) => {
      if (err) {
        console.error('Session clear error:', err);
      }
    });

    res
      .cookie(
        'access_token',
        token,
        {
          httpOnly: true,
          domain: process.env.NODE_ENV === 'production' ? '.megagera.com' : '',
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 1000 * 60 * 60
        }
      )
      .json({ success: true, user });
  } catch (error) {
    console.error('Username completion error:', error);
    res.status(400).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3150;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
