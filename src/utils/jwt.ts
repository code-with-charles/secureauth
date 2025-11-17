import jwt from 'jsonwebtoken';
import { IUser } from '../models/user.model';

const accessSecret = process.env.JWT_ACCESS_SECRET || 'access-secret';
const refreshSecret = process.env.JWT_REFRESH_SECRET || 'refresh-secret';

export const signAccessToken = (user: IUser) => {
  const payload = { sub: user._id.toString(), roles: user.roles };
  return jwt.sign(payload, accessSecret, { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '15m' });
};

export const signRefreshToken = (sessionId: string) => {
  const payload = { sid: sessionId };
  return jwt.sign(payload, refreshSecret, { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d' });
};

export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, refreshSecret) as { sid: string; iat: number; exp: number };
};
