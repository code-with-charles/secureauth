import bcrypt from 'bcrypt';
import { User } from '../models/user.model';
import { RefreshToken } from '../models/refreshToken.model';
import { genRandomString, hashToken } from '../utils/crypto';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt';
import { AuditLog } from '../models/audit.model';
import { logger } from '../server/logger';
import mongoose from 'mongoose';
import { Types } from 'mongoose';

const SALT_ROUNDS = 12;
const REFRESH_TTL_MS = (() => {
  const env = process.env.REFRESH_TOKEN_EXPIRES_IN || '30d';
  // naive parse: '30d' -> days
  if (env.endsWith('d')) return parseInt(env) * 24 * 3600 * 1000;
  return 30 * 24 * 3600 * 1000;
})();

export const register = async (email: string, password: string, name: string) => {
  const existing = await User.findOne({ email });
  if (existing) throw new Error('Email already registered');

  const hashed = await bcrypt.hash(password, SALT_ROUNDS);
  const user = await User.create({ email, password: hashed, name, verified: false, roles: ['user'] });

  // create email verification token (short lived)
  const verifyToken = genRandomString(48);
  // For simplicity, we'll generate a signed token using refresh secret semantics, but keep separate in prod.
  // Save verification in AuditLog (in real repo use dedicated model)
  await AuditLog.create({ action: 'send-verification', user: user._id, meta: { verifyToken } });

  return { user, verifyToken };
};

export const verifyEmail = async (token: string) => {
  // read the last audit for that token
  const entry = await AuditLog.findOne({ 'meta.verifyToken': token });
  if (!entry) throw new Error('Invalid verify token');
  const userId = entry.user;
  const user = await User.findByIdAndUpdate(userId, { verified: true }, { new: true });
  return user;
};

export const login = async (email: string, password: string, ip: string, deviceInfo = '') => {
  const user = await User.findOne({ email });
  if (!user) throw new Error('Invalid credentials');

  // Account lockout
  if (user.lockUntil && user.lockUntil > new Date()) throw new Error('Account locked');

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    user.failedLoginAttempts += 1;
    // if threshold reached, lock account
    if (user.failedLoginAttempts >= Number(process.env.MAX_FAILED_ATTEMPTS || 5)) {
      const backoffMs = Math.min(60 * 60 * 1000, Math.pow(2, user.failedLoginAttempts - 5) * 1000 * 60);
      user.lockUntil = new Date(Date.now() + backoffMs);
    }
    await user.save();
    await AuditLog.create({ action: 'login-failed', user: user._id, ip });
    throw new Error('Invalid credentials');
  }

  // successful login: reset counters
  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  await user.save();

  // create session (refresh token)
  const sessionId = genRandomString(24);
  const refreshTokenPlain = signRefreshToken(sessionId);
  const hashed = hashToken(refreshTokenPlain);

  const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);
  const doc = await RefreshToken.create({
    user: user._id,
    hashedToken: hashed,
    expiresAt,
    deviceInfo,
    ip,
    sessionId
  });

  const accessToken = signAccessToken(user as any);

  await AuditLog.create({ action: 'login-success', user: user._id, ip, meta: { sessionId: doc.sessionId } });

  return { accessToken, refreshToken: refreshTokenPlain, user };
};

// rotate refresh token
export const rotateRefreshToken = async (incomingToken: string, ip: string, deviceInfo = '') => {
  // verify JWT signature and get sid
  let payload;
  try {
    payload = verifyRefreshToken(incomingToken);
  } catch (err) {
    throw new Error('Invalid refresh token');
  }
  const sid = payload.sid;
  // find stored refresh token by sessionId
  const tokenDoc = await RefreshToken.findOne({ sessionId: sid });
  if (!tokenDoc) {
    // token reuse: someone used a token whose session is gone => revoke all user's sessions
    // Attempt to find user by matching hashed token to detect reuse
    const hashedIncoming = hashToken(incomingToken);
    const suspect = await RefreshToken.findOne({ hashedToken: hashedIncoming });
    if (!suspect) {
      throw new Error('Refresh token not found - possible reuse');
    }
  }

  // verify hashed token matches
  const hashedIncoming = hashToken(incomingToken);
  if (!tokenDoc.hashedToken || tokenDoc.hashedToken !== hashedIncoming) {
    // reuse detected: revoke all sessions for user
    await RefreshToken.updateMany({ user: tokenDoc.user }, { revokedAt: new Date() });
    await AuditLog.create({ action: 'refresh-reuse-detected', user: tokenDoc.user, ip, meta: { sessionId: sid } });
    throw new Error('Refresh token reuse detected');
  }

  // if expired or revoked
  if (tokenDoc.revokedAt || tokenDoc.expiresAt < new Date()) {
    throw new Error('Refresh token expired or revoked');
  }

  // rotate: create new sessionId and token, mark replacedBy
  const newSessionId = genRandomString(24);
  const newRefreshPlain = signRefreshToken(newSessionId);
  const newHashed = hashToken(newRefreshPlain);
  const newExpiresAt = new Date(Date.now() + REFRESH_TTL_MS);

  // persist: mark replacedBy and create new token document
  tokenDoc.replacedBy = newSessionId;
  tokenDoc.revokedAt = new Date();
  await tokenDoc.save();

  const newDoc = await RefreshToken.create({
    user: tokenDoc.user,
    hashedToken: newHashed,
    expiresAt: newExpiresAt,
    deviceInfo,
    ip,
    sessionId: newSessionId
  });

  // issue new access token
  const user = await (await (await import('../models/user.model')).User).findById(tokenDoc.user);
  const accessToken = signAccessToken(user as any);

  await AuditLog.create({ action: 'refresh-rotated', user: tokenDoc.user, ip, meta: { oldSession: sid, newSession: newSessionId } });

  return { accessToken, refreshToken: newRefreshPlain };
};

export const revokeRefresh = async (incomingToken: string, ip: string) => {
  let payload;
  try {
    payload = verifyRefreshToken(incomingToken);
  } catch (err) {
    return;
  }
  const sid = payload.sid;
  await RefreshToken.updateOne({ sessionId: sid }, { revokedAt: new Date() });
  await AuditLog.create({ action: 'logout', ip, meta: { sessionId: sid } });
};
