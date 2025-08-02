
import mongoose from 'mongoose';

const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // receiver of notification
  type: { type: String, required: true }, // e.g. "connection_accepted"
  message: { type: String, required: true }, // user-friendly notification message
  metadata: { type: Object }, // optional extra data, e.g. matchId
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', NotificationSchema);
export default Notification;
