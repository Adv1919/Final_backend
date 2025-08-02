import mongoose from 'mongoose';

const connectionRequestSchema = new mongoose.Schema({
  senderUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Update updatedAt on every save
connectionRequestSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

const ConnectionRequest = mongoose.model('ConnectionRequest', connectionRequestSchema);
export default ConnectionRequest;
