import express from "express";
import AuditLog from "../models/auditLog.model.js";

const router = express.Router();

// GET /admin/auditlogs - View all audit logs
router.get("/", async (req, res) => {
  try {
    const logs = await AuditLog.find()
      .populate("adminId", "username email") // Adjust fields as needed
      .sort({ timestamp: -1 }); // Latest first
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

export default router;
