import mongoose from "mongoose";

const roomSchema = new mongoose.Schema({
  roomNumber: { type: String, required: true, unique: true },
  type: { type: String, enum: ["Twin", "Single"], required: true },
  floor: { type: String },
  window: { type: Boolean },
  isOccupied: { type: Boolean, default: false },
  occupants: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // refs to User model
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Room", roomSchema);
