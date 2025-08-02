import User from "../models/user.model.js";

// List all guest profiles (users with onboarding data)
export const getAllUsers = async (req, res) => {
  try {
    // To keep it manageable, only select relevant fields for admin view
    const users = await User.find(
      {},
      {
        firstName: 1,
        lastName: 1,
        email: 1,
        "onboarding.status": 1,
        "onboarding.answers": 1,
      }
    );
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Error fetching users" });
  }
};
