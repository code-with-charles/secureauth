import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import xss from 'xss-clean';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes';
import { errorHandler } from './middlewares/error.middleware';
import { rateLimiter } from './middlewares/rate.middleware';

const app = express();

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(xss());
app.use(morgan('combined'));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Apply rate limiting to auth routes
app.use('/api/auth', rateLimiter, authRoutes);

// Example secure endpoints
app.get('/api/profile', (_req, res) => res.json({ msg: 'profile - protected example' }));

app.use(errorHandler);

export default app;
