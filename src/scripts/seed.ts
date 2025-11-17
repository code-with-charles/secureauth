import dotenv from 'dotenv';
dotenv.config();
import { connectDB } from '../config';
import { Role } from '../models/role.model';
import { User } from '../models/user.model';
import bcrypt from 'bcrypt';

(async function seed() {
  await connectDB();
  console.log('Seeding roles and admin user...');

  const roles = [
    { name: 'admin', permissions: ['users:read','users:write','users:delete'] },
    { name: 'manager', permissions: ['users:read'] },
    { name: 'user', permissions: [] }
  ];

  for (const r of roles) {
    await Role.updateOne({ name: r.name }, r, { upsert: true });
  }

  const adminEmail = process.env.SEED_ADMIN_EMAIL || 'admin@example.com';
  const adminPass = process.env.SEED_ADMIN_PASS || 'AdminPass123';
  const existing = await User.findOne({ email: adminEmail });
  if (!existing) {
    const hashed = await bcrypt.hash(adminPass, 12);
    const admin = await User.create({ email: adminEmail, password: hashed, name: 'Admin', verified: true, roles: ['admin'] });
    console.log('Admin user created:', admin.email);
  } else {
    console.log('Admin already exists');
  }

  process.exit(0);
})();
