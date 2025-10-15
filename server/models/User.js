const mongoose = require('mongoose');

// Minimal user representation used for authentication demos.
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Supports login + duplicate guard.
    password: { type: String, required: true } // Stores hashed passwords only (see controller).
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', userSchema);
