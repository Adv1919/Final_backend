import express from "express";
import { login } from "../controllers/admin.controller.js";
import adminAuth from "../middleware/admin.middleware.js";

import adminUserRoutes from "./admin.users.routes.js";
import adminRoomRoutes from "./admin.rooms.routes.js";
import adminAuditLogRoutes from "./admin.auditLog.routes.js";
import adminMatchRoutes from "./admin.match.routes.js";

const router = express.Router();

// Public login route
router.post("/login", login);

// Protected routes below require admin authentication
router.use(adminAuth);

// Mount admin sub-routes
router.use("/users", adminUserRoutes);
router.use("/rooms", adminRoomRoutes);
router.use("/matches", adminMatchRoutes);
router.use("/auditlogs", adminAuditLogRoutes);
router.use("/matches", adminMatchRoutes);

export default router;
