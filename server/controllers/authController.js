const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Handles new account creation and stores a bcrypt-hashed password.
exports.registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    console.log('↩️  Incoming register payload:', { username, email });

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Please provide username, email, and password.' });
    }

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const salt = await bcrypt.genSalt(10); // Generate per-user salt to mitigate rainbow-table attacks.
    const hashedPassword = await bcrypt.hash(password, salt); // Persist only the hash.

    const newUser = await User.create({ username, email, password: hashedPassword });
    const response = {
      message: '✅ User registered',
      user: { id: newUser._id, username: newUser.username, email: newUser.email }
    };
    console.log('✅ Register response:', response);
    res.status(201).json(response);
  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ message: 'Server Error', error: err.message });
  }
};

// Validates credentials and returns a signed JWT when successful.
exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('↩️  Incoming login payload:', { email });
    if (!email || !password) return res.status(400).json({ message: 'Please provide email and password.' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: '❌ User not found' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: '❌ Invalid password' });

    const token = jwt.sign(
      { id: user._id, email: user.email }, // JWT payload keeps identifiers minimal.
      process.env.JWT_SECRET,
      { expiresIn: '1h' } // Short-lived tokens reduce blast radius if compromised.
    );
    console.log('🔐 Generated JWT:', token);

    const response = {
      message: '✅ Login successful',
      token,
      user: { id: user._id, username: user.username, email: user.email }
    };
    console.log('✅ Login response:', response);
    res.json(response);
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ message: 'Server Error', error: err.message });
  }
};
