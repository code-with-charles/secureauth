import mongoose from 'mongoose';
const AuditSchema = new mongoose.Schema({
  action: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  ip: String,
  meta: mongoose.Schema.Types.Mixed
}, { timestamps: true });

export const AuditLog = mongoose.model('AuditLog', AuditSchema);
