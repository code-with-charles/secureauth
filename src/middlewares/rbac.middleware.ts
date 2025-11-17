import { Request, Response, NextFunction } from 'express';

export const requireRole = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    const has = user.roles && roles.some(r => user.roles.includes(r));
    if (!has) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
};
