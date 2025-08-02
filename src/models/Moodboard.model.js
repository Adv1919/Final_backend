import mongoose from "mongoose";

// Each MoodboardItem represents single post/card on the moodboard

const MoodboardItemSchema = new mongoose.Schema({
  moodboardId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Moodboard",
    required: true,
  },
  type: {
    type: String,
    enum: ["image", "note", "link", "playlist"],
    required: true,
  },
  title: { type: String },
  content: { type: String, required: true }, // URL, text, or description
  description: { type: String }, // extra info for link or playlist
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  image: { type: String }, // <-- Newly added field for link preview image URL
  createdAt: { type: Date, default: Date.now },
});

// Comments for each MoodboardItem

const MoodboardCommentSchema = new mongoose.Schema({
  itemId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "MoodboardItem",
    required: true,
  },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const MoodboardSchema = new mongoose.Schema({
  matchId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Match",
    required: true,
  },
  users: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  createdAt: { type: Date, default: Date.now },
});

export const Moodboard = mongoose.model("Moodboard", MoodboardSchema);
export const MoodboardItem = mongoose.model(
  "MoodboardItem",
  MoodboardItemSchema
);
export const MoodboardComment = mongoose.model(
  "MoodboardComment",
  MoodboardCommentSchema
);
