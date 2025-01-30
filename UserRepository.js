import DBLocal from 'db-local';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

const { Schema } = new DBLocal({ path: './db' });

// User schema
const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  permissions: { type: Array }
});

// Public User schema
const getPublicUser = (user) => {
  const { password: _, ...publicUser } = user;
  return publicUser;
};

// UserRepository class
export class UserRepository {
  // Create a new user
  static async create ({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    const user = User.findOne({ username });
    if (user) throw new Error('User already exists');

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    User.create({
      _id: id,
      username,
      password: hashedPassword,
      permissions: []
    }).save();

    return id;
  };

  // Login a user
  static async login ({ username, password }) {
    Validation.username(username);
    Validation.password(password);

    const user = User.findOne({ username });
    if (!user) throw new Error('User not found');

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error('Invalid password');

    return getPublicUser(user);
  };

  // Get all users
  static async findAll () {
    return User.find().map(getPublicUser);
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
