const jwt = require('jsonwebtoken');

// Express middleware that guards protected routes by validating the incoming JWT.
function verifyToken(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Throws when signature is invalid or token expired.
    req.user = decoded; // Downstream handlers can rely on req.user for authorization decisions.
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token.' });
  }
}

module.exports = verifyToken;
