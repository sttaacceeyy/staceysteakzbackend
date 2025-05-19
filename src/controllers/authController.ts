import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../utils/prisma';
import dotenv from 'dotenv';

import { comparePassword, hashPassword } from '../utils/hash';

dotenv.config();

export const signup = async (req: Request, res: Response): Promise<any> => {
  const { username, password } = req.body;

  const existingUser = await prisma.user.findUnique({ where: { username } });
  if (existingUser) return res.status(400).json({ message: 'Username already taken' });

  const hashedPassword = await hashPassword(password);
  const user = await prisma.user.create({
    data: {
      username,
      password: hashedPassword,
      role: 'WRITER',
    },
  });

  res.status(201).json({ message: 'User created', user: { id: user.id, username: user.username } });
};

export const login = async (req: Request, res: Response): Promise<any> => {
  const { username, password } = req.body;

  const user = await prisma.user.findUnique({ where: { username } });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const valid = await comparePassword(password, user.password);
  if (!valid) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_SECRET!, { expiresIn: '1h' });

  res.json({ token });
};