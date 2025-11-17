import Joi from 'joi';

export const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(new RegExp('(?=.*[0-9])(?=.*[A-Za-z])')).required(),
  name: Joi.string().min(1).required()
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

export const emailSchema = Joi.object({
  email: Joi.string().email().required()
});

export const resetSchema = Joi.object({
  token: Joi.string().required(),
  password: Joi.string().min(8).required()
});
