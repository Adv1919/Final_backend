import mongoose from "mongoose";

const matchSchema = new mongoose.Schema({
  user1Id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  user2Id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  roomId: { type: mongoose.Schema.Types.ObjectId, ref: "Room" }, // Assigned later
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Match", matchSchema);

