const express = require('express');
const router = express.Router();
const { registerUser, loginUser } = require('../controllers/authController');

// Public endpoints used by the React client to onboard and authenticate users.
router.post('/register', registerUser);
router.post('/login', loginUser);

module.exports = router;
