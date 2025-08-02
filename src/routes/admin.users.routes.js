import express from "express";
import {
  getAllUsersForAdmin,
  getUserByIdForAdmin,
  updateUserForAdmin,
  deleteUserForAdmin,
} from "../controllers/admin.user.controller.js";

import { validateUserUpdate } from "../middleware/validation.js";

const router = express.Router();

// GET /api/admin/users
router.get("/", getAllUsersForAdmin);

// GET /api/admin/users/:id
router.get("/:id", getUserByIdForAdmin);

// PATCH /api/admin/users/:id
router.patch("/:id", validateUserUpdate, updateUserForAdmin);

// DELETE /api/admin/users/:id
router.delete("/:id", deleteUserForAdmin);

export default router;
