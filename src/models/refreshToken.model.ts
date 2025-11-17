import mongoose, { Schema, Document } from 'mongoose';

export interface IRefreshToken extends Document {
  user: mongoose.Types.ObjectId;
  hashedToken: string; // store hashed refresh token
  expiresAt: Date;
  createdAt: Date;
  replacedBy?: string | null; // id of new token
  revokedAt?: Date | null;
  deviceInfo?: string;
  ip?: string;
  sessionId: string;
}

const RefreshTokenSchema: Schema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    hashedToken: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    replacedBy: { type: String, default: null },
    revokedAt: { type: Date, default: null },
    deviceInfo: { type: String },
    ip: { type: String },
    sessionId: { type: String, required: true }
  },
  { timestamps: true }
);

RefreshTokenSchema.index({ user: 1, sessionId: 1 });

export const RefreshToken = mongoose.model<IRefreshToken>('RefreshToken', RefreshTokenSchema);
