import Match from "../models/matchResult.model.js";

export const getAllMatchesForAdmin = async (req, res) => {
  try {
    const matches = await Match.find()
      .populate("user1Id", "firstName lastName email onboarding")
      .populate("user2Id", "firstName lastName email onboarding")
      .sort({ createdAt: -1 });

    res.json(matches);
  } catch (err) {
    console.error("Error fetching matches:", err);
    res.status(500).json({ error: "Failed to fetch matches" });
  }
};
