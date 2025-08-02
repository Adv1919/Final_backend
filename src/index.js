import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import http from "http";
import { Server as IOServer } from "socket.io";

import authRoutes from "./routes/auth.routes.js";
import userRoutes from "./routes/user.routes.js";
import surveyRoutes from "./routes/survey.routes.js";
import matchRoutes from "./routes/match.routes.js";
import adminRoutes from "./routes/admin.routes.js";
import connectionRoutes from "./routes/connection.routes.js";
import roomAllocationRoutes from "./routes/roomAllocation.routes.js";
import moodboardRoutes from './routes/moodboard.routes.js';
import roomsRouter from "./routes/room.routes.js";


import finalmatchRoutes from './routes/finalmatch.route.js';
dotenv.config();

const app = express();

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({ status: "OK" });
});

app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);
app.use("/api/survey", surveyRoutes);
app.use("/api/match", matchRoutes);
app.use("/api/finalmatch", finalmatchRoutes);

app.use("/api/connection-requests", connectionRoutes);
app.use("/api/room-allocations", roomAllocationRoutes);
app.use("/api/rooms", roomsRouter);

app.use("/api/admin", adminRoutes);
app.use('/api/moodboard', moodboardRoutes);


// -------- Centralized Error Handling Middleware --------
app.use((err, req, res, next) => {
  console.error(err.stack);
  if (res.headersSent) {
    return next(err);
  }
  res.status(err.status || 500).json({
    message: err.message || "Internal Server Error",
  });
});
// -------------------------------------------------------

// Create HTTP server for Socket.IO
const server = http.createServer(app);

// Initialize Socket.IO server
const io = new IOServer(server, {
  cors: {
    origin: "http://localhost:5173", 
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// Socket.IO connection handler
io.on("connection", (socket) => {

  
  socket.on("joinRoom", (matchId) => {
    socket.join(matchId);
  });

  // Listen for a chat message sent by client
  socket.on("sendMessage", async (data) => {
    const { matchId, message, senderUserId, senderName } = data;

    if (!data.senderUserId) {
      console.warn("Warning: senderUserId missing in received message data.");
    }

    const chatMsg = {
      _id: Date.now().toString(), // Temporary ID (use DB ID when saved)
      matchId,
      message,
      senderUserId,
      senderName,
      createdAt: new Date(),
    };

    
    socket.to(matchId).emit("receiveMessage", chatMsg);
  });

  socket.on("roomSelected", async ({ matchId, roomId }) => {
    io.to(matchId).emit("roomSelected", { roomId });
  });

  socket.on("disconnect", () => {
  });
});

// Connect to MongoDB and start the server
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected.");

    // Use `server.listen` instead of `app.listen` for Socket.IO support
    server.listen(process.env.PORT || 5000, () => {
      console.log("🚀 Server running on port " + (process.env.PORT || 5000));
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });
