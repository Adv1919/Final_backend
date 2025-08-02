import express from "express";
import mongoose from "mongoose";
import { authMiddleware } from "../middleware/auth.middleware.js";
import MatchResult from "../models/matchResult.model.js";
import User from "../models/user.model.js";

const router = express.Router();

router.get("/", authMiddleware, async (req, res) => {
  try {

    // Convert to ObjectId to ensure correct query match
    const userId = new mongoose.Types.ObjectId(req.user.id);

    const matches = await MatchResult.find({
      $or: [{ user1Id: userId }, { user2Id: userId }]
    }).lean();


    // Get array of other user ids in matches
    const otherUserIds = matches.map(m => {
      return m.user1Id.toString() === userId.toString() ? m.user2Id : m.user1Id;
    });

    const uniqueUserIds = [...new Set(otherUserIds.map(id => id.toString()))];

    const users = await User.find({ _id: { $in: uniqueUserIds } }, "firstName lastName email").lean();

    const userMap = {};
    users.forEach(u => {
      userMap[u._id.toString()] = u;
    });

    // Enrich matches with matched user info
    const enriched = matches.map(m => {
      const matchedId = m.user1Id.toString() === userId.toString() ? m.user2Id.toString() : m.user1Id.toString();
      return {
        ...m,
        matchedUser: userMap[matchedId] || null,
      };
    });

    return res.json(enriched);

  } catch (error) {
    console.error("Error fetching matches:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
});

export default router;
