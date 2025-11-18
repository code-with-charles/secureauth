# 🔐 SecureAuth – Authentication & Authorization Microservice  
Production-ready auth system built with **Node.js + Express + TypeScript + MongoDB Atlas**.

SecureAuth is a complete authentication service designed for real-world applications that need secure registration/login, JWT access tokens, rotating refresh tokens, OAuth login (Google + GitHub), RBAC, secure session handling, rate limiting, and more.

<img width="1403" height="364" alt="image" src="https://github.com/user-attachments/assets/4ebda3d5-95d6-4944-aa73-1fd9690eb575" />


## 🚀 Features

### 🔑 Authentication
- Secure **registration** & **login** (bcrypt)
- **Email verification** flow
- **Password reset** with secure token
- **Account lockout** after too many failed attempts
- Rate-limited auth endpoints (brute-force protection)

### 🔐 Token System (Best Practices)
- **Short-lived access tokens** (15 min)
- **Long-lived refresh tokens** (30 days)
- **Rotating refresh tokens** with stored session metadata
- **Reuse detection** (invalidates all sessions on theft attempt)
- HttpOnly cookies supported

### 🧑‍💼 RBAC – Role-Based Access Control
- Built-in roles: `admin`, `manager`, `user`
- Fine-grained permission middleware:
  - `requireRole(...)`
  - `requirePermission(...)`

### 🌍 OAuth2 Login
- Google OAuth
- GitHub OAuth

### 📦 Database (MongoDB Atlas)
- Users
- Refresh Tokens (hashed)
- Roles
- Permissions
- Optional Audit Logs
- Optional Redis token blacklist

### 🛡 Security
- Helmet, CORS (configurable), rate-limits
- Joi/Zod input validation
- bcrypt hashing
- Sanitization (xss-clean / express-mongo-sanitize)
- Follows OWASP API Security guidelines

### ⚙ Developer Experience
- Fully typed TypeScript codebase
- Well-structured modular architecture
- Dockerfile + docker-compose
- Jest + Supertest tests (80% coverage target)
- GitHub Actions CI (lint, test, build)
- OpenAPI (Swagger) spec included
- Postman collection included



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
