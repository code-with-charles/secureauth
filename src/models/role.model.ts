import mongoose from 'mongoose';
export const RoleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  permissions: { type: [String], default: [] }
});
export const Role = mongoose.model('Role', RoleSchema);
