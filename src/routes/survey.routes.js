import express from 'express';
import jwt from 'jsonwebtoken';
import { authMiddleware } from '../middleware/auth.middleware.js';
import User from '../models/user.model.js';

const router = express.Router();

// ✅ Track active sessions (simple in-memory storage)
let activeSessions = new Map(); // userId -> sessionInfo

// ✅ Enhanced function to get user from token with better error handling
async function getUserFromToken(token) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const userId = decoded.id || decoded.sub || decoded.userId;
    
    if (!userId) return null;
    
    const user = await User.findById(userId);
    return user;
  } catch (error) {
    console.error('❌ Token verification failed:', error.message);
    return null;
  }
}

// ✅ NEW: Register current user session
router.post('/register-session', authMiddleware, async (req, res) => {
  const userId = req.user?.id;
  if (!userId) return res.status(401).json({ message: 'Auth required' });
  
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  
  // Store active session
  activeSessions.set(userId, {
    email: user.email,
    timestamp: new Date()
  });
  
  console.log('📱 Session registered for:', user.email);
  console.log('📱 Total active sessions:', activeSessions.size);
  
  res.json({ message: 'Session registered', email: user.email });
});

// ✅ NEW: Get current active user (for webhooks)
function getCurrentActiveUser() {
  // Find most recent active session (within last 30 minutes)
  const thirtyMinsAgo = new Date(Date.now() - 30 * 60 * 1000);
  
  console.log('🔍 Checking for active sessions...');
  console.log('🔍 Total sessions:', activeSessions.size);
  
  for (let [userId, sessionInfo] of activeSessions) {
    console.log('🔍 Session found:', sessionInfo.email, 'at', sessionInfo.timestamp);
    if (sessionInfo.timestamp > thirtyMinsAgo) {
      console.log('✅ Active session found for:', sessionInfo.email);
      return userId;
    }
  }
  
  console.log('⚠️ No active sessions found');
  return null;
}

// POST /api/survey/submit - Handle both authenticated frontend AND unauthenticated webhooks
router.post('/submit', async (req, res) => {
  try {
    const raw = req.body;
    
    console.log('\n🔥🔥🔥 WEBHOOK DATA RECEIVED 🔥🔥🔥');
    console.log('📅 Timestamp:', new Date().toISOString());
    console.log('📦 RAW WEBHOOK PAYLOAD:', JSON.stringify(raw, null, 2));

    let answers;
    let isWebhook = false;
    let isAuthenticated = !!req.headers.authorization;

    // ✅ Determine data source and format
    if (raw.answers && isAuthenticated) {
      console.log('🖥️ DATA SOURCE: Authenticated frontend submission');
      answers = raw.answers;
      isWebhook = false;
    } else if (raw.call_report?.extracted_variables || raw.cleanliness_importance) {
      console.log('🎤 DATA SOURCE: Omnidim webhook (unauthenticated)');
      isWebhook = true;
      
      const extractedVars = raw.call_report?.extracted_variables || raw;
      
      if (extractedVars.command && extractedVars.command.toLowerCase() === 'submit') {
        console.log('✅ SUBMIT COMMAND DETECTED - Auto-processing webhook data...');
      } else {
        console.log('🔄 WEBHOOK DATA RECEIVED - Auto-processing without submit command...');
      }
      
      answers = {
        cleanliness: extractedVars.cleanliness_importance ? Number(extractedVars.cleanliness_importance) : null,
        sleepSchedule: extractedVars.sleep_schedule ? extractedVars.sleep_schedule.toLowerCase() : null,
        diet: extractedVars.dietary_preference ? 
          (extractedVars.dietary_preference.toLowerCase() === 'vegetarian' || extractedVars.dietary_preference.toLowerCase() === 'veg' ? 'veg' : 'non-veg') : null,
        noiseTolerance: extractedVars.noise_tolerance ? extractedVars.noise_tolerance.toLowerCase() : null,
        goal: extractedVars.current_life_goal ? extractedVars.current_life_goal.toLowerCase() : null,
      };

      // Remove null values
      Object.keys(answers).forEach(key => {
        if (answers[key] === null || answers[key] === undefined || answers[key] === '') {
          delete answers[key];
        }
      });
    } else {
      console.log('❌ UNKNOWN DATA FORMAT');
      return res.status(400).json({
        message: 'Invalid data format',
        received: raw
      });
    }

    console.log('✅ FINAL PROCESSED ANSWERS:', JSON.stringify(answers, null, 2));

    // ✅ UPDATED WEBHOOK PROCESSING - Use session-based approach
    if (isWebhook) {
      console.log('🎤 WEBHOOK AUTO-SAVE: Processing data...');
      
      let user;
      const webhookEmail = raw.user_email;
      
      // ✅ NEW: Check for active session first
      const activeUserId = getCurrentActiveUser();
      if (activeUserId) {
        user = await User.findById(activeUserId);
        if (user) {
          console.log('🎯 Using active session user:', user.email);
          console.log('🎯 Instead of webhook email:', webhookEmail);
        }
      }
      
      // Fallback to webhook email if no active session
      if (!user && webhookEmail) {
        console.log('⚠️ No active session found, falling back to webhook email');
        user = await User.findOne({ email: webhookEmail.toLowerCase() });
        if (!user) {
          user = new User({
            email: webhookEmail.toLowerCase(),
            firstName: 'Voice User',
            lastName: webhookEmail.split('@')[0],
            passwordHash: 'webhook-user-temp'
          });
          await user.save();
          console.log('✅ Created new webhook user:', user._id);
        }
      } else if (!user) {
        // Ultimate fallback
        const defaultEmail = 'webhook-default@roommatch.com';
        user = await User.findOne({ email: defaultEmail });
        if (!user) {
          user = new User({
            email: defaultEmail,
            firstName: 'Webhook',
            lastName: 'User',
            passwordHash: 'webhook-default-temp'
          });
          await user.save();
        }
      }

      console.log('🎯 FINAL USER SELECTION:', {
        userId: user._id,
        email: user.email,
        source: activeUserId ? 'active-session' : 'webhook-email-fallback'
      });

      // ✅ Store data for the selected user
      await autoUpdateUserFromWebhook(user._id, answers, res, true);
      return;
    }

    // ✅ Frontend validation (only for manual submissions)
    const requiredFields = {
      cleanliness: (val) => typeof val === 'number' && val >= 1 && val <= 5,
      sleepSchedule: (val) => typeof val === 'string' && ['early', 'late', 'flexible'].includes(val),
      diet: (val) => typeof val === 'string' && ['veg', 'non-veg'].includes(val),
      noiseTolerance: (val) => typeof val === 'string' && ['low', 'medium', 'high'].includes(val),
      goal: (val) => typeof val === 'string' && ['entrance-exam', 'college', 'job'].includes(val),
    };

    const missingFields = [];
    const invalidFields = [];

    Object.keys(requiredFields).forEach(field => {
      if (!(field in answers)) {
        missingFields.push(field);
      } else if (!requiredFields[field](answers[field])) {
        invalidFields.push(`${field}: ${answers[field]}`);
      }
    });

    if (missingFields.length > 0 || invalidFields.length > 0) {
      const errorMessage = [
        missingFields.length > 0 ? `Missing: ${missingFields.join(', ')}` : '',
        invalidFields.length > 0 ? `Invalid: ${invalidFields.join(', ')}` : ''
      ].filter(Boolean).join('. ');

      return res.status(400).json({
        message: `Validation failed. ${errorMessage}`,
        received: answers
      });
    }

    console.log('✅ FRONTEND VALIDATION PASSED');

    // ✅ Frontend handling with auth middleware
    if (!isAuthenticated) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    return authMiddleware(req, res, async () => {
      const userId = req.user?.id;
      if (!userId) {
        return res.status(401).json({ message: 'Authentication required' });
      }
      
      const authUser = await User.findById(userId);
      if (!authUser) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      await autoUpdateUserFromWebhook(userId, answers, res, false);
    });

  } catch (error) {
    console.error('💥 ERROR:', error);
    const isLikelyWebhook = req.body.call_report || req.body.cleanliness_importance;
    const statusCode = isLikelyWebhook ? 200 : 500;
    
    res.status(statusCode).json({ 
      message: isLikelyWebhook ? 'Webhook received but processing failed' : 'Server error',
      error: error.message 
    });
  }
});

// ✅ Your existing autoUpdateUserFromWebhook function remains the same
async function autoUpdateUserFromWebhook(userId, answers, res, isWebhook) {
  try {
    console.log('🚀 AUTOMATIC WEBHOOK UPDATE STARTING');
    console.log('User ID:', userId);
    console.log('Data to save:', JSON.stringify(answers, null, 2));
    
    const existingUser = await User.findById(userId);
    if (!existingUser) {
      throw new Error(`No user found with ID: ${userId}`);
    }

    console.log('📊 Updating user:', existingUser.email);
    console.log('📊 Current data:', JSON.stringify(existingUser.onboarding, null, 2));
    
    const updateFields = {};
    
    if (answers.cleanliness !== undefined) {
      updateFields['onboarding.answers.cleanliness'] = answers.cleanliness;
    }
    if (answers.sleepSchedule !== undefined) {
      updateFields['onboarding.answers.sleepSchedule'] = answers.sleepSchedule;
    }
    if (answers.diet !== undefined) {
      updateFields['onboarding.answers.diet'] = answers.diet;
    }
    if (answers.noiseTolerance !== undefined) {
      updateFields['onboarding.answers.noiseTolerance'] = answers.noiseTolerance;
    }
    if (answers.goal !== undefined) {
      updateFields['onboarding.answers.goal'] = answers.goal;
    }

    updateFields['onboarding.status'] = 'completed';

    console.log('🔄 Updating fields:', JSON.stringify(updateFields, null, 2));

    const updateResult = await User.updateOne(
      { _id: userId },
      { $set: updateFields }
    );

    console.log('📈 Update result:', {
      acknowledged: updateResult.acknowledged,
      modifiedCount: updateResult.modifiedCount,
      matchedCount: updateResult.matchedCount
    });

    const updatedUser = await User.findById(userId);
    console.log('✅ AUTOMATIC UPDATE COMPLETE');
    console.log('📊 Final data stored for:', updatedUser.email);

    res.status(200).json({
      message: `${isWebhook ? 'Webhook data automatically saved' : 'Frontend survey submitted successfully'}`,
      userId: updatedUser._id,
      userEmail: updatedUser.email,
      source: isWebhook ? 'webhook-auto' : 'frontend',
      onboarding: updatedUser.onboarding,
      redirect: '/match',
      automatic: isWebhook,
      fieldsUpdated: Object.keys(updateFields)
    });
    
  } catch (error) {
    console.error('💥 AUTOMATIC UPDATE ERROR:', error);
    
    const statusCode = isWebhook ? 200 : 500;
    res.status(statusCode).json({
      message: `Automatic update failed: ${error.message}`,
      userId: userId,
      error: error.message
    });
    
    throw error;
  }
}

router.get('/health', (req, res) => {
  res.status(200).json({ 
    message: 'Survey webhook endpoint is healthy',
    timestamp: new Date().toISOString()
  });
});

export default router;
