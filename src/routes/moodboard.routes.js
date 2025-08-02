import express from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import {
  Moodboard,
  MoodboardItem,
  MoodboardComment,
} from "../models/Moodboard.model.js";
import Match from "../models/matchResult.model.js";
import multer from "multer";
import cloudinary from "../utils/cloudinary.js"; // Your configured Cloudinary client
import { getLinkPreview } from "link-preview-js";

const router = express.Router();

// Multer setup for memory storage (buffer)
const upload = multer({ storage: multer.memoryStorage() });

// Middleware to ensure requester has access to the moodboard for the given matchId
async function requireMoodboardAccess(req, res, next) {
  const { matchId } = req.params;
  const userId = req.user.id;

  try {
    let moodboard = await Moodboard.findOne({ matchId });
    if (!moodboard) {
      // If no moodboard exists yet, create using match participants
      const match = await Match.findById(matchId);
      if (!match) return res.status(404).json({ message: "Match not found" });

      moodboard = await Moodboard.create({
        matchId,
        users: [match.user1Id, match.user2Id],
      });
    }

    // Verify user is part of this moodboard
    if (!moodboard.users.some((u) => u.toString() === userId)) {
      return res.status(403).json({ message: "Access denied" });
    }

    req.moodboard = moodboard;
    next();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error verifying access" });
  }
}

// GET moodboard items and comments for a given matchId
router.get(
  "/:matchId",
  authMiddleware,
  requireMoodboardAccess,
  async (req, res) => {
    try {
      const moodboard = req.moodboard;
      // Get items for moodboard
      const items = await MoodboardItem.find({ moodboardId: moodboard._id })
        .populate("owner", "firstName lastName email")
        .sort({ createdAt: -1 });

      // Get comments for all items
      const itemIds = items.map((i) => i._id);
      const comments = await MoodboardComment.find({ itemId: { $in: itemIds } })
        .populate("author", "firstName lastName email")
        .sort({ createdAt: 1 });

      // Include current user ID in response for frontend logic
      res.json({ moodboard, items, comments, currentUserId: req.user.id });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Failed to load moodboard data" });
    }
  }
);

// POST add new moodboard item (note, link, playlist)
// Special handling for "link" type with link preview enrichment
router.post(
  "/:matchId",
  authMiddleware,
  requireMoodboardAccess,
  async (req, res) => {
    const { type, title, content, description } = req.body;
    if (!["note", "link", "playlist"].includes(type) || !content) {
      return res
        .status(400)
        .json({ message: "Invalid data for moodboard item" });
    }

    if (type === "link") {
      // Validate URL
      try {
        new URL(content);
      } catch {
        return res.status(400).json({ message: "Invalid URL for link item." });
      }

      // Try to fetch metadata from link
      try {
        const data = await getLinkPreview(content);

        const enrichedTitle = title || data.title || "";
        const enrichedDescription = description || data.description || "";
        const enrichedImage =
          data.images && data.images.length ? data.images[0] : undefined;

        const linkItemData = {
          moodboardId: req.moodboard._id,
          type,
          title: enrichedTitle,
          content,
          description: enrichedDescription,
          owner: req.user.id,
        };

        if (enrichedImage) linkItemData.image = enrichedImage;

        const newItem = await MoodboardItem.create(linkItemData);
        return res.status(201).json(newItem);
      } catch (fetchErr) {
        console.error("Link preview fetch failed:", fetchErr);
        // Save item without enrichment if metadata fetch fails
        try {
          const newItem = await MoodboardItem.create({
            moodboardId: req.moodboard._id,
            type,
            title: title || "",
            content,
            description: description || "",
            owner: req.user.id,
          });
          return res.status(201).json(newItem);
        } catch (err) {
          console.error(err);
          return res.status(500).json({ message: "Failed to add link item" });
        }
      }
    } else {
      // Handle note and playlist as before
      try {
        const newItem = await MoodboardItem.create({
          moodboardId: req.moodboard._id,
          type,
          title,
          content,
          description,
          owner: req.user.id,
        });
        return res.status(201).json(newItem);
      } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Failed to add item" });
      }
    }
  }
);

// POST toggle like/unlike on an item
router.post("/item/:itemId/like", authMiddleware, async (req, res) => {
  try {
    const item = await MoodboardItem.findById(req.params.itemId);
    if (!item) return res.status(404).json({ message: "Item not found" });

    const userId = req.user.id;
    const index = item.likes.findIndex((u) => u.toString() === userId);
    if (index >= 0) {
      item.likes.splice(index, 1);
    } else {
      item.likes.push(userId);
    }
    await item.save();

    res.json({ liked: index < 0, likesCount: item.likes.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to toggle like" });
  }
});

// POST add comment to an item
router.post("/item/:itemId/comment", authMiddleware, async (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) {
    return res.status(400).json({ message: "Comment cannot be empty" });
  }

  try {
    const comment = await MoodboardComment.create({
      itemId: req.params.itemId,
      author: req.user.id,
      text: text.trim(),
    });
    await comment.populate("author", "firstName lastName email");
    res.status(201).json(comment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to add comment" });
  }
});

// DELETE delete a moodboard item (only owner)
router.delete("/item/:itemId", authMiddleware, async (req, res) => {
  try {
    const item = await MoodboardItem.findById(req.params.itemId);
    if (!item) return res.status(404).json({ message: "Item not found" });
    if (item.owner.toString() !== req.user.id) {
      return res.status(403).json({ message: "Unauthorized" });
    }

    // Delete associated comments
    await MoodboardComment.deleteMany({ itemId: item._id });
    await item.deleteOne();

    res.json({ message: "Item deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to delete item" });
  }
});

// DELETE delete a comment (only author)
router.delete("/comment/:commentId", authMiddleware, async (req, res) => {
  try {
    const comment = await MoodboardComment.findById(req.params.commentId);
    if (!comment) return res.status(404).json({ message: "Comment not found" });
    if (comment.author.toString() !== req.user.id) {
      return res.status(403).json({ message: "Unauthorized" });
    }
    await comment.deleteOne();
    res.json({ message: "Comment deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to delete comment" });
  }
});

// POST upload image to moodboard (handles multipart form data, uploads to Cloudinary)
router.post(
  "/:matchId/image",
  authMiddleware,
  requireMoodboardAccess,
  upload.single("image"),
  async (req, res) => {
    if (!req.file) {
      console.log("No file received in request");
      return res.status(400).json({ message: "No image file uploaded" });
    }
    console.log("File received:", req.file.originalname, req.file.mimetype);
    try {
      const streamifier = (await import("streamifier")).default;

      const uploadFromBuffer = () => {
        return new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: "moodboard_images" },
            (error, result) => {
              if (error) return reject(error);
              resolve(result);
            }
          );

          // Use createReadStream directly on streamifier, NOT call streamifier()
          streamifier.createReadStream(req.file.buffer).pipe(stream);
        });
      };

      const result = await uploadFromBuffer();

      const newItem = await MoodboardItem.create({
        moodboardId: req.moodboard._id,
        type: "image",
        content: result.secure_url,
        owner: req.user.id,
      });

      res.status(201).json(newItem);
    } catch (err) {
      console.error("Error in image upload:", err);
      res.status(500).json({ message: "Failed to upload image" });
    }
  }
);
export default router;