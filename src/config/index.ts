import mongoose from 'mongoose';
import logger from '../server/logger';

export const connectDB = async () => {
  const url = process.env.MONGODB_ATLAS_URL;
  if (!url) throw new Error('MONGODB_ATLAS_URL not configured');
  await mongoose.connect(url);
  logger.info('Connected to MongoDB Atlas');
};
