import { Request, Response, NextFunction } from 'express';
import * as authService from '../services/auth.service';
import { registerSchema, loginSchema, emailSchema, resetSchema } from '../utils/validators';
import { sendEmail } from '../services/email.service';
import { hashToken, genRandomString } from '../utils/crypto';
import { RefreshToken } from '../models/refreshToken.model';
import { signAccessToken } from '../utils/jwt';

export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    const { user, verifyToken } = await authService.register(value.email, value.password, value.name);

    const verifyUrl = `${process.env.SITE_URL}/api/auth/verify?token=${verifyToken}`;
    await sendEmail(user.email, 'Verify your email', `Click <a href="${verifyUrl}">here</a> to verify.`);

    return res.status(201).json({ message: 'Registered. Check email for verification link.' });
  } catch (err) {
    next(err);
  }
};

export const verify = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.query as { token?: string };
    if (!token) return res.status(400).json({ error: 'token required' });
    const user = await authService.verifyEmail(token);
    return res.json({ message: 'Email verified', user: { id: user._id, email: user.email } });
  } catch (err) {
    next(err);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    const ip = req.ip;
    const deviceInfo = req.headers['user-agent'] || '';
    const { accessToken, refreshToken, user } = await authService.login(value.email, value.password, ip, deviceInfo as string);

    // Set HttpOnly cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000
    };
    res.cookie('refreshToken', refreshToken, cookieOptions);

    return res.json({ accessToken, user: { id: user._id, email: user.email, name: user.name } });
  } catch (err) {
    next(err);
  }
};

export const refresh = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // prefer cookie
    const incoming = req.cookies.refreshToken || req.body.refreshToken;
    if (!incoming) return res.status(400).json({ error: 'refresh token required' });

    const ip = req.ip;
    const deviceInfo = req.headers['user-agent'] || '';
    const { accessToken, refreshToken } = await authService.rotateRefreshToken(incoming, ip, deviceInfo as string);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    return res.json({ accessToken });
  } catch (err) {
    next(err);
  }
};

export const logout = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const incoming = req.cookies.refreshToken || req.body.refreshToken || '';
    await authService.revokeRefresh(incoming, req.ip);
    res.clearCookie('refreshToken');
    return res.json({ message: 'Logged out' });
  } catch (err) {
    next(err);
  }
};

export const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = emailSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    const user = await (await import('../models/user.model')).User.findOne({ email: value.email });
    if (!user) return res.json({ message: 'If account exists, reset email sent' });

    const token = genRandomString(48);
    await (await import('../models/audit.model')).AuditLog.create({ action: 'password-reset-request', user: user._id, meta: { token }});
    const resetUrl = `${process.env.SITE_URL}/api/auth/reset-password?token=${token}`;
    await sendEmail(user.email, 'Reset your password', `Click <a href="${resetUrl}">here</a> to reset.`);

    return res.json({ message: 'If account exists, reset email sent' });
  } catch (err) {
    next(err);
  }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = resetSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.message });
    const { token, password } = value;
    // find the audit record
    const audit = await (await import('../models/audit.model')).AuditLog.findOne({ 'meta.token': token });
    if (!audit) return res.status(400).json({ error: 'Invalid token' });
    const user = await (await import('../models/user.model')).User.findById(audit.user);
    if (!user) return res.status(400).json({ error: 'Invalid token' });

    user.password = await bcryptHash(password);
    await user.save();
    await (await import('../models/audit.model')).AuditLog.create({ action: 'password-reset', user: user._id });
    return res.json({ message: 'Password reset' });
  } catch (err) {
    next(err);
  }
};

const bcryptHash = async (p: string) => {
  const bcrypt = await import('bcrypt');
  return bcrypt.hash(p, 12);
};
