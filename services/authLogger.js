import { getChannel, isConnected } from '../config/rabbitmq.js';

// Log user action to RabbitMQ
const logUserAction = async (username, action, details = {}, metadata = {}) => {
  try {
    if (!isConnected()) {
      console.warn('RabbitMQ not connected, skipping log');
      return;
    }

    const channel = getChannel();
    const logMessage = {
      timestamp: new Date().toISOString(),
      service: 'megaauth',
      username,
      action,
      details,
      metadata: {
        ip: metadata.ip || 'unknown',
        userAgent: metadata.userAgent || 'unknown',
        ...metadata
      }
    };

    await channel.sendToQueue(
      'logging',
      Buffer.from(JSON.stringify(logMessage)),
      { persistent: true } // Make message persistent
    );

    console.log(`Auth action logged: ${username} - ${action}`);
  } catch (error) {
    console.error('Failed to log auth action:', error.message);
    // Don't throw error to avoid breaking the main flow
  }
};

// Specific authentication action loggers
const logUserLogin = async (username, loginType, req) => {
  await logUserAction(
    username,
    'USER_LOGIN',
    {
      loginType // 'normal', 'test'
    },
    {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }
  );
};

const logUserRegister = async (username, req) => {
  await logUserAction(
    username,
    'USER_REGISTER',
    {

    },
    {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }
  );
};

const logTestUserCreated = async (adminUsername, testUsername, req) => {
  await logUserAction(
    adminUsername,
    'TEST_USER_CREATED',
    {
      testUsername
    },
    {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      role: 'admin'
    }
  );
};

const logPasswordChange = async (username, req) => {
  await logUserAction(
    username,
    'PASSWORD_CHANGED',
    {
    },
    {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }
  );
};

const logPasswordReset = async (adminUsername, targetUsername, req) => {
  await logUserAction(
    adminUsername,
    'PASSWORD_RESET',
    {
      targetUsername
    },
    {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      role: 'admin'
    }
  );
};

export {
  logUserAction,
  logUserLogin,
  logUserRegister,
  logTestUserCreated,
  logPasswordChange,
  logPasswordReset
};
