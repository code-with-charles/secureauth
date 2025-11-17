# SecureAuth

Secure authentication/authorization microservice (Node.js + Express + TypeScript + MongoDB Atlas)

## Requirements
- Node.js >= 18
- npm
- MongoDB Atlas URL (or local mongo)
- Optional: Redis, SendGrid

## Quick start (local)
1. copy `.env.example` -> `.env` and fill values (MONGODB_ATLAS_URL required)
2. npm install
3. npm run seed   # creates admin user and roles
4. npm run dev
5. curl http://localhost:3000/health

## Docker
docker-compose up --build

## Tests
Set MONGODB_ATLAS_URL to your test DB and run:
npm test

## Notes
- Refresh tokens are rotated. Refresh tokens are stored hashed in the DB.
- Reuse detection: if a refresh token doesn't match stored hashed token, all user's sessions are revoked.
- Cookies: refresh token set in HttpOnly secure cookie; client should use cookie for refresh.
