import DBLocal from 'db-local';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { USER_SCHEMA, extractPublicUser } from './config/userConfig.js';

const { Schema } = new DBLocal({ path: './db' });
console.log('DBLocal initialized successfully');

// User schema
const User = Schema('User', USER_SCHEMA);
console.log('User schema created successfully');

// UserRepository class
export class UserRepository {
  // Create a new user
  static async create ({ username, password, email, test = false, googleId = null, provider = 'local', needsUsername = false }) {
    Validation.username(username);

    // Only validate password if it's provided (not for OAuth users)
    if (password) {
      Validation.password(password);
    }

    if (email && email.trim() !== '') Validation.email(email);

    const user = await User.findOne({ username });
    if (user) throw new Error('User already exists');

    if (email && email.trim() !== '') {
      const emailUser = await User.findOne({ email });
      if (emailUser) throw new Error('Email already in use');
    }

    const id = crypto.randomUUID();
    // For OAuth users, use empty string instead of null
    const hashedPassword = password ? await bcrypt.hash(password, 10) : '';

    User.create({
      _id: id,
      username,
      password: hashedPassword,
      email: email && email.trim() !== '' ? email : '',
      permissions: [Permission.generateMegaGoal()],
      test,
      googleId: googleId || '',
      provider,
      needsUsername
    }).save();

    return id;
  };

  // Create or find Google OAuth user
  static async createOrFindGoogleUser ({ googleId, email }) {
    // First, try to find by Google ID
    let user = await User.findOne({ googleId });

    if (user) {
      return extractPublicUser(user);
    }

    // If not found by Google ID, try to find by email
    user = await User.findOne({ email });
    if (user) {
      // Update existing user with Google ID
      user.googleId = googleId;
      user.provider = 'google';
      await user.save();
      return extractPublicUser(user);
    }

    // Create new user - always require username selection for new Google users
    const username = 'temp_' + Date.now();
    const id = await this.create({
      username,
      password: '', // Use empty string instead of null
      email,
      googleId,
      provider: 'google',
      needsUsername: true // Always require username selection for new Google users
    });

    // Return the created user
    user = await User.findOne({ _id: id });
    return extractPublicUser(user);
  };

  // Login a user
  static async login ({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    // Try to find user by username first, then by email
    let user = await User.findOne({ username });
    if (!user) {
      // If not found by username, try by email
      user = await User.findOne({ email: username });
    }
    if (!user) throw new Error('User not found');

    // Check if user has a password (not OAuth-only user)
    if (!user.password || user.password === '') {
      throw new Error('This account uses social login');
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error('Invalid password');

    return extractPublicUser(user);
  };

  // Get all users
  static async findAll () {
    return User.find().map(extractPublicUser);
  }

  // Get a random test user
  static async findRandomTestUser () {
    const testUsers = User.find({ test: true });
    if (testUsers.length === 0) {
      throw new Error('No test users found');
    }
    const randomIndex = Math.floor(Math.random() * testUsers.length);
    const randomTestUser = testUsers[randomIndex];
    return extractPublicUser(randomTestUser);
  }

  // Delete a user
  static async delete ({ username }) {
    const user = await User.findOne({ username });
    if (!user) {
      throw new Error('User not found');
    }

    // Use the remove method on the user instance
    await user.remove();
    return user._id;
  }

  static async updatePermissions ({ username, permissions, action }) {
    const user = await User.findOne({ username });
    if (!user) throw new Error('User not found');
    if (action) {
      const permission = Permission.generate(permissions);
      if (user.permissions.some(p => (p.type === permission.type && permission.type === 'admin') ||
        (p.name === permission.name))) {
        throw new Error('Permission already exists');
      }
      user.permissions = [...user.permissions, permission];
    } else {
      if (permissions === 'admin') {
        if (!user.permissions.some(p => p.type === 'admin')) {
          throw new Error('Permission not found');
        } else {
          user.permissions = user.permissions.filter(p => p.type !== 'admin');
        }
      } else {
        if (!user.permissions.some(p => p.name === permissions)) {
          throw new Error('Permission not found');
        } else {
          user.permissions = user.permissions.filter(p => p.name !== permissions);
        }
      }
      user.permissions = user.permissions.filter(p => p.name !== permissions);
    }
    await user.save();
    return user._id;
  }

  // Change user password
  static async changePassword ({ username, oldPassword, newPassword }) {
    Validation.username(username);
    Validation.password(newPassword);

    const user = await User.findOne({ username });
    if (!user) throw new Error('User not found');

    const isValid = await bcrypt.compare(oldPassword, user.password);
    if (!isValid) throw new Error('Old password is invalid');

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    return user._id;
  }

  // Reset user password by admin
  static async resetPassword ({ username }) {
    Validation.username(username);

    const user = await User.findOne({ username });
    if (!user) throw new Error('User not found');

    const newPassword = username;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    return user._id;
  }

  // Complete Google OAuth user setup with username
  static async completeGoogleUserSetup ({ googleId, username }) {
    Validation.username(username);

    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log('Username already exists');
      throw new Error('Username already exists');
    }

    // Find the Google user by googleId
    const user = await User.findOne({ googleId });
    if (!user) {
      console.log('Google user not found');
      throw new Error('Google user not found');
    }
    // Update user with chosen username
    user.username = username;
    user.needsUsername = false;

    await user.save();
    console.log('User saved successfully');

    const result = extractPublicUser(user);
    return result;
  };

  // Check if username is available
  static async checkUsernameAvailability ({ username }) {
    Validation.username(username);

    const existingUser = await User.findOne({ username });
    return !existingUser; // Return true if available, false if taken
  };

  // Find user by ID (for deserializeUser)
  static async findById (id) {
    const user = await User.findOne({ _id: id });
    if (!user) throw new Error('User not found');
    return extractPublicUser(user);
  };
}

// Validation class
class Validation {
  // Validations. Optional -> Use zod
  static username (username) {
    if (typeof username !== 'string') throw new Error('Username must be a string');
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('Password must be a string');
  }

  static email (email) {
    if (typeof email !== 'string') throw new Error('Email must be a string');
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) throw new Error('Invalid email address');
  }
}

// Permission class
class Permission {
  static generate (name) {
    switch (name) {
      case 'admin':
        return Permission.generateAdmin();
      case 'megadocu':
        return Permission.generateMegaDocu();
      case 'megagoal':
        return Permission.generateMegaGoal();
      case 'megamedia':
        return Permission.generateMegaMedia();
      default:
        throw new Error('Invalid permission');
    }
  }

  static generateAdmin () {
    return { type: 'admin' };
  }

  static generateMegaDocu () {
    return { type: 'access', name: 'megadocu', url: 'https://megadocu.megagera.com' };
  }

  static generateMegaGoal () {
    const apikey = crypto.randomUUID().replace(/-/g, '');
    return { type: 'access', name: 'megagoal', url: 'https://megagoal.megagera.com', apikey };
  }

  static generateMegaMedia () {
    return { type: 'access', name: 'megamedia', url: 'https://megamedia.megagera.com' };
  }
}
