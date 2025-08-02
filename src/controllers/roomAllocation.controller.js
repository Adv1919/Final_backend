import RoomAllocation from "../models/roomAllocation.model.js";
import Room from "../models/room.model.js";
import Match from "../models/matchResult.model.js";

// Helper: determine max capacity based on room type
const roomCapacity = (room) => (room.type === "Twin" ? 2 : 1);

// Helper: check if room has available spots
const isRoomAvailable = (room) => room.occupants.length < roomCapacity(room);

export const createRoomAllocation = async (matchId, session = null) => {
  try {
    // Check if allocation already exists for this match
    let allocation = session
      ? await RoomAllocation.findOne({ matchId }).session(session)
      : await RoomAllocation.findOne({ matchId });

    if (allocation) return allocation;

    // Fetch the Match document (using the correct matchId)
    const match = session
      ? await Match.findById(matchId).session(session)
      : await Match.findById(matchId);

    if (!match) throw new Error("Match not found");

    // Define allocatorUserId - e.g., pick user1 as the allocator by default
    const allocatorUserId = match.user1Id;

    allocation = new RoomAllocation({
      matchId,
      allocatorUserId,
      selectedRoomId: null,
      isConfirmed: false,
    });

    if (session) await allocation.save({ session });
    else await allocation.save();

    return allocation;
  } catch (error) {
    console.error("Error creating room allocation:", error);
    throw error;
  }
};

// Get allocation by matchId (the Match document's _id)
export const getRoomAllocationByMatchId = async (req, res) => {
  try {
    const { matchId } = req.params;

    const allocation = await RoomAllocation.findOne({ matchId })
      .populate("selectedRoomId")
      .populate("allocatorUserId", "firstName lastName email");

    if (!allocation) return res.status(404).json({ message: "Room allocation not found" });

    res.json(allocation);
  } catch (error) {
    console.error("Error fetching room allocation:", error);
    res.status(500).json({ message: "Error fetching room allocation" });
  }
};

// Allocator selects room and confirms allocation
export const selectRoomForAllocation = async (req, res) => {
  try {
    const { matchId } = req.params;
    const { roomId } = req.body;
    // userId of logged-in user
    const userId = req.user._id || req.user.id;

    // Fetch allocation by matchId 
    const allocation = await RoomAllocation.findOne({ matchId });
    if (!allocation) return res.status(404).json({ message: "Room allocation not found" });

    // Only allocator can select room
    if (!allocation.allocatorUserId.equals(userId))
      return res.status(403).json({ message: "Not authorized to select room" });

    if (allocation.isConfirmed)
      return res.status(400).json({ message: "Room allocation already confirmed" });

    // Check room availability
    const room = await Room.findById(roomId).populate("occupants");
    if (!room) return res.status(404).json({ message: "Room not found" });

    if (!isRoomAvailable(room))
      return res.status(400).json({ message: "Selected room is full" });

    // Update allocation with selected room and mark confirmed
    allocation.selectedRoomId = roomId;
    allocation.isConfirmed = true;
    await allocation.save();

    // Add both users (from Match document) as occupants to the room
    // Fetch match to get involved users
    const match = await Match.findById(matchId);
    if (!match) return res.status(404).json({ message: "Match not found" });

    const occupantsToAdd = new Set([
      match.user1Id.toString(),
      match.user2Id.toString(),
    ]);

    occupantsToAdd.forEach((uid) => {
      if (!room.occupants.find((o) => o.toString() === uid)) {
        room.occupants.push(uid);
      }
    });

    // Mark room as occupied if full
    room.isOccupied = room.occupants.length >= roomCapacity(room);
    await room.save();

    res.json({ message: "Room allocated successfully", allocation });
  } catch (error) {
    console.error("Error selecting room for allocation:", error);
    res.status(500).json({ message: "Error selecting room for allocation" });
  }
};

// Chat features placeholders
export const getChatMessages = async (req, res) => {
  res.status(501).json({ message: "Chat feature not implemented yet" });
};

export const postChatMessage = async (req, res) => {
  res.status(501).json({ message: "Chat feature not implemented yet" });
};
