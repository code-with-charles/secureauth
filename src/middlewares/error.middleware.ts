import { Request, Response, NextFunction } from 'express';
import { logger } from '../server/logger';

export const errorHandler = (err: any, _req: Request, res: Response, _next: NextFunction) => {
  logger.error(err);
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  res.status(status).json({ error: message });
};
