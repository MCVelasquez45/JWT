# MERN JWT Build-Along (Student Guide)

This guide walks you through wiring the entire authentication flow inside the `student/` workspace. Every step includes the exact code (with comments) you should paste into the matching file so the whole cohort moves in sync. Keep the finished `client/` and `server/` folders nearby if you want to compare behaviour after each milestone.

---

## 0. Prerequisites

- Node 16+ installed
- MongoDB running locally (or replace the URI below with your Atlas connection string)
- Two terminals ready:
  - Terminal A → `/student/server`
  - Terminal B → `/student/client`
- Keep both the browser console and your server terminal visible; we added logs you’ll use for debugging.

---

## 1. Install Dependencies (includes bcrypt & JWT)

All required packages (Express, Mongoose, `bcryptjs`, `jsonwebtoken`, etc.) are already listed in `package.json`. You just need to install them.

```bash
# Terminal A – server deps (installs express, mongoose, bcryptjs, jsonwebtoken, …)
cd student/server
npm install

# Terminal B – client deps (installs React, Axios, React Router, …)
cd student/client
npm install
```

---

## 2. Configure the Server

### 2.1 Environment variables

File: `student/server/.env`

```env
##### Server Environment #####
PORT=4545
MONGO_URI=mongodb://127.0.0.1:27017/jwtauth
JWT_SECRET=supersecretkey123
CLIENT_ORIGIN=http://localhost:3000
```

- `JWT_SECRET` should be rotated outside of training.
- `CLIENT_ORIGIN` must match the React dev server URL so CORS succeeds.

### 2.2 Server bootstrap

Copy everything below into `student/server/server.js` (replace the placeholder file).

**What this file does**
- Loads environment variables and connects to MongoDB before handling requests.
- Configures CORS so the React app can talk to the API.
- Parses JSON, logs every request, and mounts the auth/private routes.
- Starts the Express server on the configured port.

```js
// student/server/server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const privateRoutes = require('./routes/privateRoutes');

/**
 * Entry point for the JWT training API.
 * Responsibilities:
 * - load environment config
 * - connect to MongoDB
 * - configure middleware (CORS, logging, JSON body parsing)
 * - mount authentication and private routes
 * - start the Express server
 */
// Load environment variables before attempting DB connection or server start.
dotenv.config();
connectDB();

// Explicit CORS configuration allows the React client to send credentials and auth headers.
const corsOptions = {
  origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

const app = express();
app.use(cors(corsOptions)); // Apply CORS rules to every request.
app.options('*', cors(corsOptions)); // Handle preflight requests explicitly.
app.use(express.json()); // Parse incoming JSON bodies (register/login payloads).

// Teacher-friendly logging: surface every request body alongside the route hit.
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`, req.body || {});
  next();
});

// Mount JWT-related routes under the /api namespace.
app.use('/api/auth', authRoutes);
app.use('/api/private', privateRoutes);

const PORT = process.env.PORT || 4545;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

```

### 2.3 Mongo connection helper

**What this helper does**
- Uses Mongoose to connect to MongoDB using `MONGO_URI`.
- Logs success so you can verify the server is ready.
- Exits the process if the connection fails (to avoid a broken API).

File: `student/server/config/db.js`

```js
// student/server/config/db.js
const mongoose = require('mongoose');

/**
 * connectDB()
 * Establishes a MongoDB connection using Mongoose.
 * - Resolves when the database is reachable.
 * - Throws and exits the process on failure so the API never runs half-configured.
 */
// Centralized connection helper so the app fails fast if MongoDB is unreachable.
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`❌ Mongo Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
```

### 2.4 User model

**What this model does**
- Defines the MongoDB schema for users.
- Enforces unique emails and required fields.
- Saves password hashes without ever storing plaintext credentials.

File: `student/server/models/User.js`

```js
// student/server/models/User.js
const mongoose = require('mongoose');

/**
 * User schema for the training project.
 * We persist username + email + hashed password and rely on timestamps for auditing.
 */
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
```

### 2.5 Auth controllers

**What these controllers do**
- `registerUser`: validates inputs, prevents duplicates, hashes passwords, and returns a safe summary.
- `loginUser`: validates credentials, verifies the stored hash, signs a JWT, and returns the token.

File: `student/server/controllers/authController.js`

```js
// student/server/controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * registerUser()
 * Handles the whole registration lifecycle:
 * - validate incoming fields
 * - check for duplicate emails
 * - generate salt + hash the password
 * - persist the new user and return a safe response
 *
 * loginUser()
 * Authenticates a user and issues a JWT:
 * - validate input
 * - fetch the user, compare bcrypt hash
 * - sign a short-lived token
 * - respond with token + lightweight user profile
 */
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
```

### 2.6 JWT middleware

**What this middleware does**
- Extracts the token from the `Authorization` header.
- Verifies the signature/expiry using `JWT_SECRET`.
- Populates `req.user` for downstream handlers or returns 401/403 errors.

File: `student/server/middleware/authMiddleware.js`

```js
// student/server/middleware/authMiddleware.js
const jwt = require('jsonwebtoken');

/**
 * verifyToken middleware
 * - ensures an Authorization header exists
 * - validates the JWT signature/expiry
 * - attaches the decoded payload to req.user
 * - returns 401/403 when verification fails
 */
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
```

### 2.7 Routes

**What these routes do**
- `authRoutes`: expose `/register` and `/login` for public use by the React app.
- `privateRoutes`: guard `/dashboard` behind the JWT middleware to demonstrate protected access.

`authRoutes` (public) and `privateRoutes` (protected).

```js
// student/server/routes/authRoutes.js
const express = require('express');
const router = express.Router();
const { registerUser, loginUser } = require('../controllers/authController');

/**
 * Auth routes expose public registration and login endpoints.
 * POST /register -> create user account.
 * POST /login -> authenticate and receive token.
 */
// Public endpoints used by the React client to onboard and authenticate users.
router.post('/register', registerUser);
router.post('/login', loginUser);

module.exports = router;
```

```js
// student/server/routes/privateRoutes.js
const express = require('express');
const router = express.Router();
const verifyToken = require('../middleware/authMiddleware');

/**
 * Private routes demonstrate JWT protection.
 * The dashboard handler assumes verifyToken ran and attached req.user.
 */
// Example protected route — only reachable when verifyToken attaches a valid req.user.
router.get('/dashboard', verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}! You have access.` });
});

module.exports = router;
```

---

## 3. Build the Client

This section replicates the React logic required to talk to the API.

### 3.1 Axios helpers

**What these helpers do**
- Centralize all HTTP requests so components can stay focused on UI.
- Log both requests and responses for visibility during the workshop.

File: `student/client/src/api/auth.js`

```js
// student/client/src/api/auth.js
import axios from 'axios';

// Centralizes API calls so components only worry about data, not request details.
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:4545';

export const loginUser = async (email, password) => {
  try {
    const payload = { email, password };
    console.log('➡️  Login request:', payload);
    const res = await axios.post(`${API_BASE_URL}/api/auth/login`, payload);
    console.log('⬅️  Login response:', res.data);
    return res.data;
  } catch (error) {
    console.error('❌ Login error:', error.response?.data || error.message);
    throw error;
  }
};

export const registerUser = async (username, email, password) => {
  try {
    const payload = { username, email, password };
    console.log('➡️  Register request:', payload);
    const res = await axios.post(`${API_BASE_URL}/api/auth/register`, payload);
    console.log('⬅️  Register response:', res.data);
    return res.data;
  } catch (error) {
    console.error('❌ Register error:', error.response?.data || error.message);
    throw error;
  }
};
```

### 3.2 Sign-in page

**What this component does**
- Manages form state for registration and login within a single view.
- Switches modes with one toggle and reuses the same submit handler.
- Stores the JWT on successful login and redirects to the dashboard.

File: `student/client/src/pages/SignInPage.jsx`

```jsx
// student/client/src/pages/SignInPage.jsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { loginUser, registerUser } from '../api/auth';

/**
 * SignInPage
 * Unified UI for registration and sign-in.
 * - toggles between modes with local state
 * - calls the appropriate API helper
 * - stores the JWT on successful login
 * - redirects to the dashboard once authenticated
 */
export default function SignInPage() {
  // Local state mirrors the form fields so we can submit or reset them easily.
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const toggleMode = () => {
    setIsRegistering(!isRegistering);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (isRegistering) {
        console.log('📝 Sending register form', { username, email, password });
        await registerUser(username, email, password);
        alert('Registration successful. You can now sign in.');
        setIsRegistering(false);
      } else {
        console.log('🔐 Sending login form', { email, password });
        const data = await loginUser(email, password);
        if (data?.token) {
          console.log('💾 Storing token', data);
          localStorage.setItem('token', data.token); // Persist token for subsequent requests.
          navigate('/dashboard');
        }
      }
    } catch (error) {
      const message =
        error.response?.data?.message ||
        error.message ||
        'Something went wrong. Please try again.';
      alert(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5">
      <h2 className="text-center mb-3">{isRegistering ? 'Register' : 'Sign In'}</h2>
      <form onSubmit={handleSubmit} className="mx-auto" style={{ maxWidth: '400px' }}>
        {isRegistering && (
          <div className="mb-3">
            <label className="form-label">Username:</label>
            <input
              type="text"
              className="form-control"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
        )}
        <div className="mb-3">
          <label className="form-label">Email:</label>
          <input
            type="email"
            className="form-control"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="mb-3">
          <label className="form-label">Password:</label>
          <input
            type="password"
            className="form-control"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit" className="btn btn-primary w-100" disabled={loading}>
          {loading ? 'Please wait…' : isRegistering ? 'Register' : 'Login'}
        </button>
      </form>
      <div className="text-center mt-3">
        <button type="button" className="btn btn-link" onClick={toggleMode}>
          {isRegistering ? 'Already have an account? Sign in' : "Don't have an account? Register"}
        </button>
      </div>
    </div>
  );
}
```

### 3.3 Dashboard page

**What this component does**
- Reads the stored token, requests protected data, and displays the welcome message.
- Handles logout by clearing the token and redirecting home.
- Shows friendly messages if the user is unauthenticated or the token is invalid.

File: `student/client/src/pages/Dashboard.jsx`

```jsx
// student/client/src/pages/Dashboard.jsx
import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

/**
 * Dashboard
 * Fetches protected content using the stored JWT.
 * - redirects unauthenticated users back to the sign-in page
 * - displays the personalized welcome message from the API
 * - offers a logout button that clears the token
 */
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:4545';

export default function Dashboard() {
  const [message, setMessage] = useState('');
  const navigate = useNavigate();

  const logout = () => {
    localStorage.removeItem('token'); // Drop the JWT so subsequent requests fail fast.
    navigate('/');
  };

  useEffect(() => {
    const fetchData = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        setMessage('Please log in first.');
        return;
      }

      try {
        console.log('📡 Fetching dashboard with token', token);
        const res = await axios.get(`${API_BASE_URL}/api/private/dashboard`, {
          headers: { Authorization: `Bearer ${token}` } // Mirror the header the middleware checks.
        });
        console.log('📨 Dashboard response', res.data);
        setMessage(res.data.message);
      } catch (error) {
        console.error('❌ Dashboard error:', error.response?.data || error.message);
        setMessage('Access denied. Invalid or expired token.');
      }
    };

    fetchData();
  }, []);

  return (
    <div className="container mt-5 text-center">
      <h3 className="mb-3">{message}</h3>
      <button className="btn btn-secondary" onClick={logout}>
        Logout
      </button>
    </div>
  );
}
```

---

## 4. Run the Stack

1. **Start the API**
   ```bash
   cd student/server
   npm run dev
   ```
   - Watch for `✅ MongoDB Connected` and `🚀 Server running on port 4545`.

2. **Start the React client**
   ```bash
   cd student/client
   npm start
   ```
   - Browser should open at `http://localhost:3000`.

3. **Test the flow**
   - Register a new user.
   - Sign in with the same credentials.
   - Observe the token in `localStorage` and the dashboard welcome message.

---

## 5. Data Flow Checkpoints

### Registration
```
[React SignInPage] ==> [registerUser helper] ==> POST /api/auth/register
      └── logs payload in browser console
             |
[authController.registerUser]
      ├── validates fields
      ├── checks duplicates
      ├── bcrypt.genSalt + bcrypt.hash
      └── stores user in Mongo
             |
Response 201 with user summary (no password)
```

### Login + Protected Route
```
[React SignInPage] ==> [loginUser helper] ==> POST /api/auth/login
      └── logs response containing token
             |
localStorage saves token
      |
Axios GET /api/private/dashboard with Authorization: Bearer <token>
      |
[verifyToken middleware] verifies JWT and attaches req.user
      |
[Route handler] responds "Welcome <email>! You have access."
```

---

## 6. Stretch Experiments

1. **Trigger failure states**
   - Submit the login form with a wrong password → expect 400.
   - Remove the `Bearer ` prefix in the dashboard request to see a 401.
   - Paste a tampered token into `localStorage` to provoke a 403.

2. **Add a `role` field**
   - Extend the registration form, schema, and token payload to include `role`.
   - Display the role on the dashboard.

3. **Switch storage**
   - Experiment with HTTP-only cookies instead of `localStorage` and compare pros/cons.

Document your observations—you’ll compare notes during the debrief.
