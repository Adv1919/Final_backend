import AuditLog from "../models/auditLog.model.js";

export async function logAdminAction(
  adminId,
  action,
  collectionName,
  documentId = null,
  details = {}
) {
  try {
    const log = new AuditLog({
      adminId,
      action,
      collectionName,
      documentId,
      details,
    });
    await log.save();
  } catch (error) {
    console.error("Failed to save audit log", error);
  }
}
