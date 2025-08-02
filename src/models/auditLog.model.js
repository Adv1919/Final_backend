import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema({
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Admin",
    required: true,
  },
  action: { type: String, required: true },
  collectionName: { type: String, required: true },
  documentId: { type: mongoose.Schema.Types.ObjectId },
  timestamp: { type: Date, default: Date.now },
  details: { type: Object, default: {} },
});

export default mongoose.model("AuditLog", auditLogSchema);
