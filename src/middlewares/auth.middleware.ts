import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.model';

export const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Unauthorized' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET || 'access-secret') as any;
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ error: 'Invalid token' });
    (req as any).user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};
