import dotenv from 'dotenv';

const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env.development';
dotenv.config({ path: envFile });

if (!process.env.SECRET_JWT_KEY) {
  console.error('Missing environment variables: SECRET_JWT_KEY');
  process.exit(1);
}
