import { Router } from 'express';
import { login, signup, refreshToken } from '../controllers/authController';

const router = Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/refresh', refreshToken);

export default router;
