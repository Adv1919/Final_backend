import User from "../models/user.model.js";

export const getAllUsersForAdmin = async (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ message: "Error fetching users" });
  }
};

export const getUserByIdForAdmin = async (req, res) => {
  try {
    const user = await User.findById(req.params.id, {
      firstName: 1,
      lastName: 1,
      email: 1,
      onboarding: 1,
    });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Error fetching user" });
  }
};

export const updateUserForAdmin = async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true,
    });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (error) {
    res
      .status(400)
      .json({ message: "Failed to update user", error: error.message });
  }
};

export const deleteUserForAdmin = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Failed to delete user" });
  }
};
