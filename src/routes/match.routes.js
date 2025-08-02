import express from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import User from "../models/user.model.js";
import ConnectionRequest from "../models/connectionRequest.model.js";
import Match from "../models/matchResult.model.js"; // use your exact model name here

const router = express.Router();

/**
 * Compute compatibility score (out of 100) and reasons between two users.
 * @param {Object} a - Onboarding answers of userA
 * @param {Object} b - Onboarding answers of userB
 * @returns {score: Number, reasons: String[]}
 */
function computeCompatibilityScore(a, b) {
  let rawScore = 0;
  const reasons = [];

  // Cleanliness (scale 1-5)
  if ("cleanliness" in a && "cleanliness" in b) {
    const diff = Math.abs(a.cleanliness - b.cleanliness);
    if (diff === 0) {
      rawScore += 3;
      reasons.push("Both have the same cleanliness level.");
    } else if (diff === 1) {
      rawScore += 1;
      reasons.push("Cleanliness levels are close.");
    }
  }

  // Sleep Schedule
  if (a.sleepSchedule && b.sleepSchedule && a.sleepSchedule === b.sleepSchedule) {
    rawScore += 3;
    reasons.push("Both have the same sleep schedule.");
  }

  // Diet
  if (a.diet && b.diet && a.diet === b.diet) {
    rawScore += 2;
    reasons.push("Both follow the same diet.");
  }

  // Noise Tolerance
  if (a.noiseTolerance && b.noiseTolerance && a.noiseTolerance === b.noiseTolerance) {
    rawScore += 1;
    reasons.push("Both have the same noise tolerance level.");
  }

  // Goal
  if (a.goal && b.goal && a.goal === b.goal) {
    rawScore += 1;
    reasons.push("Both share similar goals.");
  }

  const maxScore = 10;
  const scoreOutOf100 = Math.round((rawScore / maxScore) * 100);

  return { score: scoreOutOf100, reasons };
}

router.get("/", authMiddleware, async (req, res) => {
  try {
    const userId = String(req.user.id);

    // 1. Get user IDs current user is already matched with (status: accepted)
    const acceptedConns = await ConnectionRequest.find({
      status: "accepted",
      $or: [{ senderUserId: userId }, { receiverUserId: userId }],
    });
    const matchedUserIds = new Set();
    acceptedConns.forEach((conn) => {
      matchedUserIds.add(
        String(conn.senderUserId) === userId ? String(conn.receiverUserId) : String(conn.senderUserId)
      );
    });

    // 2. Get all users who have two or more accepted matches
    // Aggregation on both user1Id and user2Id in Match collection
    const matchCounts1 = await Match.aggregate([
      { $group: { _id: "$user1Id", count: { $sum: 1 } } },
    ]);
    const matchCounts2 = await Match.aggregate([
      { $group: { _id: "$user2Id", count: { $sum: 1 } } },
    ]);
    const countsMap = new Map();
    [...matchCounts1, ...matchCounts2].forEach((u) => {
      countsMap.set(String(u._id), (countsMap.get(String(u._id)) || 0) + u.count);
    });

    // Users at max 2 matches or more
    const maxedOutUserIds = new Set();
    for (const [id, count] of countsMap.entries()) {
      if (count >= 2) maxedOutUserIds.add(id);
    }

    // 3. Get users rejected by or who have rejected current user
    const rejectedConns = await ConnectionRequest.find({
      status: "rejected",
      $or: [{ senderUserId: userId }, { receiverUserId: userId }],
    });
    const rejectedUserIds = new Set();
    rejectedConns.forEach((conn) => {
      // Add the user who is NOT the current user
      if (String(conn.senderUserId) === userId) rejectedUserIds.add(String(conn.receiverUserId));
      else rejectedUserIds.add(String(conn.senderUserId));
    });

    // 4. Find all eligible users (completed onboarding, exclude current user)
    const otherUsers = await User.find({
      _id: { $ne: userId },
      "onboarding.status": "completed",
    }).lean();

    // 5. Filter out matched, maxed out, and rejected users
    const filteredUsers = otherUsers.filter(
      (u) =>
        !matchedUserIds.has(u._id.toString()) &&
        !maxedOutUserIds.has(u._id.toString()) &&
        !rejectedUserIds.has(u._id.toString())
    );

    // 6. Compute compatibility score for each filtered user relative to current user
    // Get current user onboarding answers for comparison
    const currentUser = await User.findById(userId).lean();
    if (!currentUser || !currentUser.onboarding || !currentUser.onboarding.answers) {
      return res.status(400).json({ message: "Current user has not completed onboarding." });
    }
    const currentAnswers = currentUser.onboarding.answers;

    const matchesWithScores = filteredUsers.map((user) => {
      // Ensure user also completed onboarding with answers
      if (!user.onboarding || !user.onboarding.answers) {
        return null; // skip users without answers
      }
      const comp = computeCompatibilityScore(currentAnswers, user.onboarding.answers);
      return {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        compatibilityScore: comp.score,
        compatibilityReasons: comp.reasons,
        // add other user fields you want to expose
      };
    }).filter(Boolean); // remove nulls

    // 7. Sort by compatibility score descending
    matchesWithScores.sort((a, b) => b.compatibilityScore - a.compatibilityScore);

    return res.json(matchesWithScores);

  } catch (err) {
    console.error("Error fetching matches:", err);
    res.status(500).json({ message: "Server error." });
  }
});

export default router;
