import express from "express";
import mongoose from "mongoose";
import ConnectionRequest from "../models/connectionRequest.model.js";
import Match from "../models/matchResult.model.js";
import Notification from "../models/notification.model.js";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { createRoomAllocation } from "../controllers/roomAllocation.controller.js";

const router = express.Router();

// Send a new connection request
router.post("/", authMiddleware, async (req, res) => {
  const senderUserId = String(req.user.id);
  const receiverUserId = String(req.body.receiverUserId);

  try {
    // 1. Prevent sending request to yourself
    if (senderUserId === receiverUserId) {
      return res.status(400).json({ message: "Cannot connect with yourself." });
    }

    // 2. Prevent sending request if sender or receiver already has 2 matches
    const senderCount = await Match.countDocuments({
      $or: [{ user1Id: senderUserId }, { user2Id: senderUserId }],
    });

    if (senderCount >= 2) {
      return res.status(409).json({ message: "You have already reached 2 matches." });
    }

    const receiverCount = await Match.countDocuments({
      $or: [{ user1Id: receiverUserId }, { user2Id: receiverUserId }],
    });

    if (receiverCount >= 2) {
      return res.status(409).json({ message: "User is at maximum matches." });
    }

    // 3. Check if already matched (in Match collection)
    const alreadyMatched = await Match.findOne({
      $or: [
        { user1Id: senderUserId, user2Id: receiverUserId },
        { user1Id: receiverUserId, user2Id: senderUserId },
      ],
    });

    if (alreadyMatched) {
      return res.status(409).json({ message: "Already matched." });
    }

    // 4. Check if connection was previously rejected either way in ConnectionRequest
    const rejected = await ConnectionRequest.findOne({
      status: "rejected",
      $or: [
        { senderUserId, receiverUserId },
        { senderUserId: receiverUserId, receiverUserId: senderUserId },
      ],
    });

    if (rejected) {
      return res.status(409).json({ message: "Connection was previously rejected." });
    }

    // 5. Prevent duplicate active requests (pending or accepted) in either direction
    const existing = await ConnectionRequest.findOne({
      $or: [
        { senderUserId, receiverUserId },
        { senderUserId: receiverUserId, receiverUserId: senderUserId },
      ],
      status: { $in: ["pending", "accepted"] },
    });

    if (existing) {
      return res.status(400).json({ message: "Connection request already exists." });
    }

    // 6. Create new connection request
    const newRequest = new ConnectionRequest({ senderUserId, receiverUserId });
    await newRequest.save();

    return res.status(201).json({ message: "Request sent.", request: newRequest });
  } catch (err) {
    console.error("Error creating connection request:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

// Get incoming pending connection requests for logged-in user
router.get("/incoming", authMiddleware, async (req, res) => {
  try {
    const requests = await ConnectionRequest.find({
      receiverUserId: req.user.id,
      status: "pending",
    }).populate("senderUserId", "firstName lastName email");

    res.json(requests);
  } catch (err) {
    console.error("Error fetching incoming requests:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// Get pending outgoing connection requests sent by logged-in user
router.get("/pending-sent", authMiddleware, async (req, res) => {
  try {
    const pendingSent = await ConnectionRequest.find({
      senderUserId: req.user.id,
      status: "pending",
    }).populate("receiverUserId", "firstName lastName email");
    res.json(pendingSent);
  } catch (error) {
    console.error("Error fetching pending sent requests:", error);
    res.status(500).json({ message: "Failed to fetch pending requests." });
  }
});

// Get accepted connections for logged-in user
router.get("/accepted", authMiddleware, async (req, res) => {
  const userId = String(req.user.id);
  try {
    const accepted = await ConnectionRequest.find({
      status: "accepted",
      $or: [{ senderUserId: userId }, { receiverUserId: userId }],
    })
      .populate("senderUserId", "firstName lastName email onboarding")
      .populate("receiverUserId", "firstName lastName email onboarding");

    // Normalize so frontend easily sees the "otherUser"
    const normalized = accepted.map((conn) => {
      const senderId = String(conn.senderUserId._id || conn.senderUserId);
      const receiverId = String(conn.receiverUserId._id || conn.receiverUserId);
      let otherUser = null;

      if (senderId === userId) otherUser = conn.receiverUserId;
      else if (receiverId === userId) otherUser = conn.senderUserId;

      return {
        _id: conn._id,
        status: conn.status,
        otherUser,
        senderUserId: conn.senderUserId,
        receiverUserId: conn.receiverUserId,
        createdAt: conn.createdAt,
        updatedAt: conn.updatedAt,
      };
    });

    res.json(normalized);
  } catch (err) {
    console.error("Error fetching accepted connections:", err);
    res.status(500).json({ message: "Failed to fetch accepted connections." });
  }
});

// Accept or reject a connection request, with transactional room allocation on acceptance
router.post("/:requestId/respond", authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();

  try {
    const { requestId } = req.params;
    const { status } = req.body; // 'accepted' or 'rejected'
    const currentUserId = String(req.user.id);

    if (!["accepted", "rejected"].includes(status)) {
      return res.status(400).json({ message: "Invalid status value." });
    }

    await session.startTransaction();

    const request = await ConnectionRequest.findById(requestId).session(session);
    if (!request) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: "Request not found." });
    }

    const senderUserId = String(request.senderUserId);
    const receiverUserId = String(request.receiverUserId);

    if (currentUserId !== receiverUserId) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ message: "Not authorized to respond." });
    }

    if (request.status !== "pending") {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: "Request already responded to." });
    }

    // If accepting, enforce max matches limit (up to 2)
    if (status === "accepted") {
      const existingMatchCount = await Match.countDocuments({
        $or: [{ user1Id: currentUserId }, { user2Id: currentUserId }],
      }).session(session);

      if (existingMatchCount >= 2) {
        await session.abortTransaction();
        session.endSession();
        return res.status(400).json({ message: "You can have only up to 2 matches." });
      }
    }

    // Update request status
    request.status = status;
    await request.save({ session });

    if (status === "accepted") {
      // Prevent duplicate match creation
      const existingMatch = await Match.findOne({
        $or: [
          { user1Id: senderUserId, user2Id: receiverUserId },
          { user1Id: receiverUserId, user2Id: senderUserId },
        ],
      }).session(session);

      if (existingMatch) {
        await session.abortTransaction();
        session.endSession();
        return res.status(400).json({ message: "Match already exists." });
      }

      // Create new match document
      const newMatch = new Match({
        user1Id: senderUserId,
        user2Id: receiverUserId,
      });
      await newMatch.save({ session });

      // Send notification to sender about acceptance
      await Notification.create(
        [
          {
            userId: senderUserId,
            type: "connection_accepted",
            message: "Your connection request has been accepted! You are now matched.",
            metadata: { matchId: newMatch._id.toString() },
            read: false,
          },
        ],
        { session }
      );

      // Create room allocation (pass session for transaction)
      await createRoomAllocation(newMatch._id, session);

      await session.commitTransaction();
      session.endSession();

      return res.json({ message: "Request accepted.", match: newMatch });
    } else {
      // On rejection: simply commit transaction, no notification sent
      await session.commitTransaction();
      session.endSession();

      console.log(`Request ${requestId} rejected.`);
      return res.json({ message: "Request rejected." });
    }
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error("Error responding to connection request:", err);
    return res.status(500).json({ message: err.message || "Server error." });
  }
});
// GET /connection-requests/rejected - get all rejected connection requests involving current user
router.get("/rejected", authMiddleware, async (req, res) => {
  const userId = String(req.user.id);
  try {
    const rejectedRequests = await ConnectionRequest.find({
      status: "rejected",
      $or: [
        { senderUserId: userId },
        { receiverUserId: userId },
      ],
    }).populate("senderUserId receiverUserId", "firstName lastName email");

    res.json(rejectedRequests);
  } catch (error) {
    console.error("Error fetching rejected connection requests:", error);
    res.status(500).json({ message: "Server error." });
  }
});


// Get unread notifications for current user
router.get("/notifications", authMiddleware, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user.id, read: false }).sort({ createdAt: -1 });
    res.json(notifications);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ message: "Error fetching notifications." });
  }
});

// Mark notifications as read
router.post("/notifications/mark-read", authMiddleware, async (req, res) => {
  const { notificationIds } = req.body;

  if (!Array.isArray(notificationIds)) {
    return res.status(400).json({ message: "notificationIds must be an array." });
  }

  try {
    await Notification.updateMany(
      { userId: req.user.id, _id: { $in: notificationIds } },
      { $set: { read: true } }
    );
    res.json({ message: "Notifications marked as read." });
  } catch (error) {
    console.error("Error marking notifications as read:", error);
    res.status(500).json({ message: "Failed to mark notifications as read." });
  }
});

export default router;
