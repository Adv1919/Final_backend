import express from "express";
import {
  getAllRooms,
  addRoom,
  getRoomById,
  updateRoom,
  deleteRoom,
} from "../controllers/admin.room.controller.js";

import {
  validateRoomCreate,
  validateRoomUpdate,
} from "../middleware/validation.js";

const router = express.Router();

// List all rooms
router.get("/", getAllRooms);

// Create a new room - requires roomNumber and type
router.post("/", validateRoomCreate, addRoom);

// Get room by ID
router.get("/:id", getRoomById);

// Update room - fields optional but validated if provided
router.patch("/:id", validateRoomUpdate, updateRoom);

// Delete a room by ID
router.delete("/:id", deleteRoom);

export default router;
