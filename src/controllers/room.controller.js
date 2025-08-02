import Room from "../models/room.model.js";

// List all rooms
export const getAllRooms = async (req, res) => {
  try {
    const rooms = await Room.find().populate(
      "occupants",
      "firstName lastName email"
    );
    res.json(rooms);
  } catch (error) {
    console.error("Error fetching rooms:", error);
    res.status(500).json({ message: "Error fetching rooms" });
  }
};

// Add a new room
export const addRoom = async (req, res) => {
  try {
    const { roomNumber, type, floor, window } = req.body;
    const room = new Room({ roomNumber, type, floor, window });
    await room.save();
    res.status(201).json(room);
  } catch (error) {
    console.error("Error adding room:", error);
    res.status(400).json({ message: "Error adding room" });
  }
};
