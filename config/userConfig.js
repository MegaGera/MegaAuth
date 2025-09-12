// User Schema Configuration
export const USER_SCHEMA = {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: false }, // Made optional for OAuth users
  email: { type: String, required: false },
  permissions: { type: Array },
  test: { type: Boolean, required: false },
  googleId: { type: String, required: false }, // Added for Google OAuth
  provider: { type: String, required: false }, // Added to track auth provider
  needsUsername: { type: Boolean, required: false }
};

// JWT Payload Configuration - Fields to include in JWT token
export const JWT_PAYLOAD_FIELDS = ['id', 'username', 'email', 'permissions', 'test', 'provider'];

// Public User Fields - Fields to return in API responses (excluding password)
export const PUBLIC_USER_FIELDS = ['_id', 'username', 'email', 'permissions', 'test', 'googleId', 'provider'];

// Helper function to extract user data for JWT payload
export const extractJwtPayload = (user) => {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    permissions: user.permissions,
    test: user.test,
    provider: user.provider || 'local'
  };
};

// Helper function to extract public user data (excluding password)
export const extractPublicUser = (user) => {
  const { password: _, ...publicUser } = user;
  return publicUser;
};
