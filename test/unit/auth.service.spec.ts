import { rotateRefreshToken } from '../../src/services/auth.service';
import { genRandomString, hashToken } from '../../src/utils/crypto';
import { RefreshToken } from '../../src/models/refreshToken.model';
import mongoose from 'mongoose';

describe('AuthService - rotateRefreshToken', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_ATLAS_URL || 'mongodb://localhost:27017/secureauth_test');
    await RefreshToken.deleteMany({});
  });
  afterAll(async () => {
    await mongoose.disconnect();
  });

  it('rotates refresh token and revokes old one', async () => {
    const sessionId = genRandomString(24);
    const oldToken = genRandomString(64);
    // insert a doc
    const doc = await RefreshToken.create({
      user: new mongoose.Types.ObjectId(),
      hashedToken: hashToken(oldToken),
      expiresAt: new Date(Date.now() + 1000 * 60 * 60),
      sessionId
    });
    // call rotateRefreshToken using a JWT-like token; but rotateRefreshToken expects a signed JWT.
    // Here we simulate by signing with same secret using utils.jwt.signRefreshToken
    const { signRefreshToken } = require('../../src/utils/jwt');
    const signed = signRefreshToken(sessionId);
    const result = await rotateRefreshToken(signed, '127.0.0.1', 'jest');
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
    const newDoc = await RefreshToken.findOne({ sessionId: result.refreshToken ? result.refreshToken.slice(0, 1) : { $exists: true } });
    // check old doc revoked
    const old = await RefreshToken.findById(doc._id);
    expect(old?.revokedAt).toBeTruthy();
  });
});
