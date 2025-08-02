import express from "express";
import { getAllRooms, addRoom } from "../controllers/room.controller.js";
import adminAuth from "../middleware/admin.middleware.js";

const router = express.Router();

// Public route to get all rooms
router.get("/", getAllRooms);

// Admin-only route to add a new room
router.post("/", adminAuth, addRoom);

export default router;
