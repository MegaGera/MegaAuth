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

// Trust proxy for HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  // Force HTTPS redirect in production
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

// Connect to RabbitMQ for logging
connectRabbitMQ();

// Simple in-memory store for Google user data during username selection
const googleUserStore = new Map();

app.set('view engine', 'ejs');

app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: true, // Changed to true to ensure session is saved
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60, // 1 hour
    httpOnly: true,
    sameSite: 'strict'
  },
  name: 'connect.sid' // Explicit session name
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.NODE_ENV === 'production'
    ? 'https://megaauth.megagera.com/auth/google/callback'
    : '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const { id, emails } = profile;
    const email = emails[0].value;

    // Create or find user
    const user = await UserRepository.createOrFindGoogleUser({
      googleId: id,
      email
    });

    return done(null, user);
  } catch (error) {
    console.error('Google OAuth Strategy error:', error);
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

    // If user doesn't exist (was deleted), return null instead of error
    if (!user) {
      return done(null, false);
    }

    done(null, user);
  } catch (error) {
    console.error('Deserialize user error:', error);
    // Return null instead of error to prevent session issues
    done(null, false);
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

  if (!token) {
    return res.render('login');
  }

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
        await logUserRegister(username, 'normal', req);

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
      await logUserRegister(username, 'normal', req);
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
    console.error('Delete user error:', error);
    console.error('Error stack:', error.stack);
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
  // Clear Passport user data manually (avoid req.logout() to prevent session errors)
  if (req.session) {
    // Clear passport data from session
    if (req.session.passport) {
      delete req.session.passport;
    }

    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
    });
  }

  // Clear JWT token cookie (this is the main logout for regular users)
  res.clearCookie('access_token', {
    domain: process.env.NODE_ENV === 'production' ? '.megagera.com' : '',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });

  // Clear session cookie
  res.clearCookie('connect.sid', {
    domain: process.env.NODE_ENV === 'production' ? '.megagera.com' : '',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  });

  return res.json({ message: 'Logged out' });
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
        // Store user in memory store and redirect to username selection
        const storeKey = req.sessionID;
        googleUserStore.set(storeKey, user);

        res.redirect('/username-selection');
        return;
      }

      // User already has username, proceed with login
      const token = jwt.sign(
        extractJwtPayload(user),
        process.env.SECRET_JWT_KEY,
        { expiresIn: '1h' }
      );

      await logUserLogin(user.username, 'google', req);

      // Set the JWT cookie first, then redirect to completion page
      const userData = {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.displayName
      };

      const redirectUrl = req.query.redirect || '/';

      // Create a completion page that will handle the JSON response
      const completionHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Completing Google Login...</title>
        </head>
        <body>
          <p>Completing Google login...</p>
          <script>
            // Simulate the JSON response that would be sent
            const responseData = {
              success: true,
              redirectUrl: '${redirectUrl}',
              user: ${JSON.stringify(userData)},
              token: '${token}'
            };
            
            // Redirect to the specified URL
            window.location.href = responseData.redirectUrl;
          </script>
        </body>
        </html>
      `;

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
        .send(completionHtml);
      // Clear the Passport session after setting the cookie
      if (req.session) {
        req.session.destroy((err) => {
          if (err) {
            console.error('Error destroying session:', err);
          }
        });
      }
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      res.redirect('/login?error=oauth_failed');
    }
  }
);

// Username selection page
app.get('/username-selection', (req, res) => {
  // Check if user is in memory store
  const storeKey = req.sessionID;
  const googleUser = googleUserStore.get(storeKey);

  if (!googleUser) {
    return res.redirect('/login');
  }

  // Check if user needs username selection

  if (!googleUser.needsUsername && !googleUser.username.startsWith('temp_')) {
    return res.redirect('/');
  }

  res.render('username-selection');
});

// Check username availability
app.post('/auth/google/check-username', async (req, res) => {
  try {
    const { username } = req.body;

    const isAvailable = await UserRepository.checkUsernameAvailability({ username });

    res.json({ available: isAvailable });
  } catch (error) {
    console.error('Username check error:', error);
    console.error('Error stack:', error.stack);
    res.status(400).json({ error: error.message });
  }
});

// Complete username setup
app.post('/auth/google/complete', async (req, res) => {
  try {
    const { username } = req.body;

    // Check if user is in memory store
    const storeKey = req.sessionID;
    const googleUser = googleUserStore.get(storeKey);

    if (!googleUser) {
      console.error('No Google user in memory store');
      return res.status(400).json({ error: 'No Google user in memory store' });
    }

    try {
      const user = await UserRepository.completeGoogleUserSetup({
        googleId: googleUser.googleId,
        username
      });
      const token = jwt.sign(
        extractJwtPayload(user),
        process.env.SECRET_JWT_KEY,
        { expiresIn: '1h' }
      );
      await logUserRegister(user.username, 'google', req);
      googleUserStore.delete(storeKey);
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
      console.error('Error stack:', error.stack);
      res.status(400).json({ error: error.message });
    }
  } catch (outerError) {
    console.error('Outer error in /auth/google/complete:', outerError);
    console.error('Outer error stack:', outerError.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Global error handler
process.on('uncaughtException', (error) => {
  console.error('=== UNCAUGHT EXCEPTION ===');
  console.error('Error:', error);
  console.error('Error stack:', error.stack);
  console.error('Error name:', error.name);
  console.error('Error message:', error.message);
  console.error('========================');

  // Don't exit on session-related errors, just log them
  if (error.message && error.message.includes('regenerate')) {
    console.error('Session error detected, continuing...');
    return;
  }

  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('=== UNHANDLED REJECTION ===');
  console.error('Promise:', promise);
  console.error('Reason:', reason);
  console.error('Reason stack:', reason.stack);
  console.error('==========================');

  // Don't exit on session-related errors, just log them
  if (reason && reason.message && reason.message.includes('regenerate')) {
    console.error('Session error detected, continuing...');
    return;
  }

  process.exit(1);
});

// Add process monitoring and graceful shutdown
let serverInstance = null;

process.on('exit', (code) => {
});

process.on('SIGTERM', () => {
  gracefulShutdown();
});

process.on('SIGINT', () => {
  gracefulShutdown();
});

function gracefulShutdown () {
  if (serverInstance) {
    serverInstance.close(() => {
      process.exit(0);
    });

    // Force exit after 5 seconds if server doesn't close
    setTimeout(() => {
      process.exit(1);
    }, 5000);
  } else {
    process.exit(0);
  }
}

const PORT = process.env.PORT || 3150;
serverInstance = app.listen(PORT, () => {
});
