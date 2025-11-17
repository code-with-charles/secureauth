import rateLimit from 'express-rate-limit';

export const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX || 100),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
});
