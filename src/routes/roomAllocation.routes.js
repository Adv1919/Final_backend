import express from "express";
import {
  getRoomAllocationByMatchId,
  selectRoomForAllocation,
  getChatMessages,
  postChatMessage,
} from "../controllers/roomAllocation.controller.js";
import { authMiddleware }  from "../middleware/auth.middleware.js"; 

const router = express.Router();

router.get("/:matchId", authMiddleware, getRoomAllocationByMatchId);

router.post("/:matchId/select-room", authMiddleware, selectRoomForAllocation);

router.get("/:matchId/chat", authMiddleware, getChatMessages);
router.post("/:matchId/chat", authMiddleware, postChatMessage);

export default router;
