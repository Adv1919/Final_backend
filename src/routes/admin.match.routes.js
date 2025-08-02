import express from "express";
import adminAuth from "../middleware/admin.middleware.js";
import { getAllMatchesForAdmin } from "../controllers/admin.match.controller.js";

const router = express.Router();

// Apply adminAuth middleware to all routes in this router
router.use(adminAuth);

// GET /admin/matches
router.get("/", getAllMatchesForAdmin);

export default router;
