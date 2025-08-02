import Room from "../models/room.model.js";
import { logAdminAction } from "../utils/auditLogger.js";

export const getAllRooms = async (req, res) => {
  try {
    const rooms = await Room.find().populate(
      "occupants",
      "firstName lastName email"
    );
    res.json(rooms);
  } catch (error) {
    res.status(500).json({ message: "Error fetching rooms" });
  }
};

export const addRoom = async (req, res) => {
  try {
    const { roomNumber, type, floor, window } = req.body;
    const room = new Room({ roomNumber, type, floor, window });
    await room.save();

    await logAdminAction(req.admin.id, "CREATE", "Room", room._id, {
      roomNumber,
      type,
      floor,
      window,
    });

    res.status(201).json(room);
  } catch (error) {
    res.status(400).json({ message: "Error adding room" });
  }
};

export const getRoomById = async (req, res) => {
  try {
    const room = await Room.findById(req.params.id).populate(
      "occupants",
      "firstName lastName email"
    );
    if (!room) return res.status(404).json({ message: "Room not found" });
    res.json(room);
  } catch (error) {
    res.status(500).json({ message: "Error fetching room" });
  }
};

export const updateRoom = async (req, res) => {
  try {
    const updates = req.body;
    const room = await Room.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true,
    });
    if (!room) return res.status(404).json({ message: "Room not found" });

    await logAdminAction(req.admin.id, "UPDATE", "Room", room._id, updates);

    res.json(room);
  } catch (error) {
    res
      .status(400)
      .json({ message: "Failed to update room", error: error.message });
  }
};

export const deleteRoom = async (req, res) => {
  try {
    const room = await Room.findByIdAndDelete(req.params.id);
    if (!room) return res.status(404).json({ message: "Room not found" });

    await logAdminAction(req.admin.id, "DELETE", "Room", room._id);
    if (!room) return res.status(404).json({ message: "Room not found" });
    res.json({ message: "Room deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Failed to delete room" });
  }
};
