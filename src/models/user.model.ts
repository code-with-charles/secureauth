import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
  email: string;
  password: string;
  name: string;
  verified: boolean;
  roles: string[]; // e.g., ['user']
  failedLoginAttempts: number;
  lockUntil?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

const UserSchema: Schema = new Schema(
  {
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    verified: { type: Boolean, default: false },
    roles: { type: [String], default: ['user'] },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null }
  },
  { timestamps: true }
);

export const User = mongoose.model<IUser>('User', UserSchema);
