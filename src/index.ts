import dotenv from 'dotenv';
dotenv.config();
import app from './app';
import { connectDB } from './config';
import { logger } from './server/logger';

const PORT = process.env.PORT || 3000;

(async function start() {
  try {
    await connectDB();
    app.listen(PORT, () => {
      logger.info(`SecureAuth listening on http://localhost:${PORT}`);
    });
  } catch (err) {
    logger.error('Failed to start server', err);
    process.exit(1);
  }
})();
