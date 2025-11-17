import crypto from 'crypto';

export const hashToken = (token: string) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

export const genRandomString = (len = 48) =>
  crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
