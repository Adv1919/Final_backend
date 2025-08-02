import express from 'express';
import User from '../models/user.model.js';
import { authMiddleware } from '../middleware/auth.middleware.js';

const router = express.Router();

// GET /api/user/profile - get user profile, protected route
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash'); // Exclude passwordHash
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      onboarding: user.onboarding
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching user profile' });
  }
});

export default router;
