import { Router } from 'express';
import * as authController from '../controllers/auth.controller';

const router = Router();

router.post('/register', authController.register);
router.get('/verify', authController.verify);
router.post('/login', authController.login);
router.post('/refresh', authController.refresh);
router.post('/logout', authController.logout);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// OAuth placeholder: redirects and callbacks
router.get('/oauth/:provider', async (req, res) => {
  // redirect to provider auth page handled by oauth.service or passport in full app
  res.json({ message: 'OAuth start - configure provider in env' });
});
router.get('/oauth/:provider/callback', async (req, res) => {
  res.json({ message: 'OAuth callback - implement provider flow' });
});

export default router;
