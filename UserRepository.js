import DBLocal from 'db-local';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { USER_SCHEMA, extractPublicUser } from './config/userConfig.js';

const { Schema } = new DBLocal({ path: './db' });

// User schema
const User = Schema('User', USER_SCHEMA);

// UserRepository class
export class UserRepository {
  // Create a new user
  static async create ({ username, password, email, test = false }) {
    Validation.username(username);
    Validation.password(password);
    if (email && email.trim() !== '') Validation.email(email);

    const user = User.findOne({ username });
    if (user) throw new Error('User already exists');

    if (email && email.trim() !== '') {
      const emailUser = User.findOne({ email });
      if (emailUser) throw new Error('Email already in use');
    }

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    User.create({
      _id: id,
      username,
      password: hashedPassword,
      email: email && email.trim() !== '' ? email : '',
      permissions: [Permission.generateMegaGoal()],
      test: test
    }).save();

    return id;
  };

  // Login a user
  static async login ({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    // Try to find user by username first, then by email
    let user = User.findOne({ username });
    if (!user) {
      // If not found by username, try by email
      user = User.findOne({ email: username });
    }
    if (!user) throw new Error('User not found');

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
    const user = User.findOne({ username });
    if (!user) throw new Error('User not found');
    user.remove();
    return user._id;
  }

  static async updatePermissions ({ username, permissions, action }) {
    const user = User.findOne({ username });
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
    user.save();
    return user._id;
  }

  // Change user password
  static async changePassword ({ username, oldPassword, newPassword }) {
    Validation.username(username);
    Validation.password(newPassword);

    const user = User.findOne({ username });
    if (!user) throw new Error('User not found');

    const isValid = await bcrypt.compare(oldPassword, user.password);
    if (!isValid) throw new Error('Old password is invalid');

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.save();

    return user._id;
  }

  // Reset user password by admin
  static async resetPassword ({ username }) {
    Validation.username(username);

    const user = User.findOne({ username });
    if (!user) throw new Error('User not found');

    const newPassword = username;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.save();

    return user._id;
  }
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
