import request from 'supertest';
import app from '../../src/app';
import mongoose from 'mongoose';
import { User } from '../../src/models/user.model';

describe('Auth routes', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_ATLAS_URL || 'mongodb://localhost:27017/secureauth_test');
    await User.deleteMany({});
  });
  afterAll(async () => {
    await mongoose.disconnect();
  });

  it('register -> login -> refresh -> logout', async () => {
    const email = 'ituser@example.com';
    const password = 'Password123';
    const name = 'IT User';
    await request(app).post('/api/auth/register').send({ email, password, name }).expect(201);

    const loginRes = await request(app).post('/api/auth/login').send({ email, password }).expect(200);
    expect(loginRes.body.accessToken).toBeDefined();
    const cookies = loginRes.headers['set-cookie'];
    expect(cookies).toBeDefined();

    // use refresh cookie
    const refreshRes = await request(app).post('/api/auth/refresh').set('Cookie', cookies).expect(200);
    expect(refreshRes.body.accessToken).toBeDefined();

    await request(app).post('/api/auth/logout').set('Cookie', cookies).expect(200);
  });
});
