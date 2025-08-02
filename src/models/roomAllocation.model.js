import mongoose from "mongoose";

const roomAllocationSchema = new mongoose.Schema(
  {
    matchId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Match", 
      required: true,
      unique: true, 
    },
    allocatorUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true, 
    },
    selectedRoomId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Room",
      default: null,
    },
    isConfirmed: {
      type: Boolean,
      default: false, 
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("RoomAllocation", roomAllocationSchema);
