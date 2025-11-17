import nodemailer from 'nodemailer';
import logger from '../server/logger';

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;

const createTransport = async () => {
  if (SENDGRID_API_KEY) {
    // Using SendGrid SMTP config via nodemailer sendMail; or ideal: @sendgrid/mail
    return nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      auth: { user: 'apikey', pass: SENDGRID_API_KEY }
    });
  }

  // Fallback to ethereal for dev or SMTP passed in env
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.ethereal.email',
    port: Number(process.env.SMTP_PORT) || 587,
    auth: {
      user: process.env.SMTP_USER || '',
      pass: process.env.SMTP_PASS || ''
    }
  });
  return transporter;
};

export const sendEmail = async (to: string, subject: string, html: string) => {
  const transporter = await createTransport();
  const from = process.env.EMAIL_FROM || 'noreply@example.com';
  try {
    const info = await transporter.sendMail({ from, to, subject, html });
    logger.info('Email sent', info);
    return info;
  } catch (err) {
    logger.error('Failed to send email', err);
    throw err;
  }
};
