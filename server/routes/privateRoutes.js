const express = require('express');
const router = express.Router();
const verifyToken = require('../middleware/authMiddleware');

// Example protected route — only reachable when verifyToken attaches a valid req.user.
router.get('/dashboard', verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}! You have access.` });
});

module.exports = router;
