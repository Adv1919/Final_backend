import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';

// Register controller
export async function register(req, res) {
  const { firstName, lastName, email, password } = req.body;

  // Validate input
  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Check if user exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(409).json({ message: 'User already exists' });
  }

  // Hash password
  const passwordHash = await bcrypt.hash(password, 10);

  // Create user
  const user = await User.create({
    firstName,
    lastName,
    email,
    passwordHash
  });

  // Sign JWT token (expires in 2 hours)
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '12h' });

  // Respond with token and user info (exclude password)
  res.json({
    token,
    user: {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      onboarding: user.onboarding
    }
  });
}

// Login controller
export async function login(req, res) {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  // Find user by email
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Compare password hashes
  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Sign JWT
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '12h'});

  res.json({
    token,
    user: {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      onboarding: user.onboarding
    }
  });
}
