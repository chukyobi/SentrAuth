import { Request, Response } from 'express';
import { hashPassword, verifyPassword } from '../utils/passwordUtils';
import { generateTokens, verifyRefreshToken } from '../utils/jwtUtils';
import { prisma } from '../utils/prismaClient';

export const signup = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const hashed = await hashPassword(password);
    const user = await prisma.user.create({
      data: { email, password: hashed },
    });

    const tokens = generateTokens(user);
    res.status(201).json({ user, ...tokens });
  } catch (err) {
    res.status(500).json({ error: 'Signup failed' });
  }
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await verifyPassword(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const tokens = generateTokens(user);
    res.json({ user, ...tokens });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
};

export const refreshToken = async (req: Request, res: Response) => {
  const { token } = req.body;

  try {
    const user = await verifyRefreshToken(token);
    const tokens = generateTokens(user);
    res.json(tokens);
  } catch (err) {
    res.status(403).json({ error: 'Invalid refresh token' });
  }
};
