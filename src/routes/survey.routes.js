import express from 'express';
import { authMiddleware } from '../middleware/auth.middleware.js';
import User from '../models/user.model.js';

const router = express.Router();

// POST /api/survey/submit
router.post('/submit', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const answers = req.body.answers;

  // Define required fields and their expected types or enum values
  const requiredFields = {
    cleanliness: (val) => typeof val === 'number' && val >= 1 && val <= 5,
    sleepSchedule: (val) => ['early', 'late', 'flexible'].includes(val),
    diet: (val) => ['veg', 'non-veg'].includes(val),
    noiseTolerance: (val) => ['low', 'medium', 'high'].includes(val),
    goal: (val) => ['entrance-exam', 'college', 'job'].includes(val),
  };

  // Validate presence and correctness of all required fields
  if (
    !answers ||
    typeof answers !== 'object' ||
    Object.keys(requiredFields).some(
      (field) => !(field in answers) || !requiredFields[field](answers[field])
    )
  ) {
    return res.status(400).json({
      message: `Invalid or incomplete survey data. Required fields: ${Object.keys(requiredFields).join(
        ', '
      )}`,
    });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update onboarding answers and status
    user.onboarding.answers = answers;
    user.onboarding.status = 'completed';

    await user.save();

    res.status(200).json({
      message: 'Survey submitted successfully',
      onboarding: user.onboarding,
    });
  } catch (error) {
    console.error('Survey submission error:', error);
    res.status(500).json({ message: 'Server error submitting survey' });
  }
});

export default router;