import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
  firstName:     { type: String, required: true },
  lastName:      { type: String, required: true },
  email:         { type: String, required: true, unique: true },
  passwordHash:  { type: String, required: true },

  onboarding: {
    status: { type: String, default: 'pending' }, // 'pending' or 'complete'
    answers: {
      cleanliness:      { type: Number, min:1, max:5, default: 3 },
      sleepSchedule:    { type: String, enum: ['early', 'late', 'flexible'], default: 'flexible' },
      diet:             { type: String, enum: ['veg', 'non-veg'], default: 'veg' },
      noiseTolerance:   { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
      goal:             { type: String, enum: ['entrance-exam', 'college', 'job'], default: 'college' }
    }
  }
});

const User = mongoose.model('User', UserSchema);
export default User;