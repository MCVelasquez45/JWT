# MERN JWT Build Session (Instructor Guide)

## Overview
Guide your cohort through completing the scaffolded `student/` project, rebuilding registration, JWT issuance, and middleware protections while mirroring the finished implementation in `server/` and `client/`. The plan below pairs each milestone with the final code (including inline comments) and detailed coaching notes so you can narrate the why behind every line.

### Learning Outcomes
- Configure an Express server with CORS, logging, and MongoDB connectivity.
- Implement secure registration (bcrypt hashing, duplicate guards) and JWT-based login.
- Protect routes with JWT middleware and consume them from a React client.

### Prep Checklist
- Dependencies installed: `npm install` in `student/server` and `student/client`.
- Environment file ready: `student/server/.env` contains training-safe defaults.
- Optional comparison: keep `server/` and `client/` open to reference the completed code.

---

## Session Flow

### 1. Orientation (5 min)
- Highlight the three workspaces:
  - `student/server` & `student/client`: scaffolds with `LESSON STEP` comments and `501` placeholders.
  - `server/` & `client/`: finished implementation to confirm expectations.
  - `student/student.md`: learner worksheet matching this agenda.
- Run both student apps. Expect `501` responses until endpoints are wired:
  ```bash
  cd student/server && npm run dev
  cd student/client && npm start
  ```

---

### 2. Server Bootstrapping (10 min)
Build out `student/server/server.js`, explaining each moving part. Use the finished file for reference:

```js
// server/server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const privateRoutes = require('./routes/privateRoutes');

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
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

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

Talking points:
- `dotenv.config()` must run before anything that reads `process.env`.
- CORS options whitelist the React dev server and expose the `Authorization` header for JWTs.
- Logging middleware is purely observational—no mutation—making it safe for production demos.
- Route mounting clarifies the separation between public auth endpoints and protected resources.

---

### Registration & Login Flow Map
Use this ASCII diagram to orient learners before touching controllers.

```text
                   ┌─────────────────────────┐
                   │ React SignInPage form   │
                   └─────────────┬───────────┘
                                 │ submit (register/login)
                    ┌────────────▼──────────┐
                    │ Axios helper (auth.js)│
                    └───────┬───────────────┘
                            │ POST /api/auth/register
                            │ or POST /api/auth/login
             ┌──────────────▼───────────────┐
             │ Express route (authRoutes)   │
             └──────────────┬───────────────┘
                            │ invokes controller
            ┌───────────────▼────────────────┐
            │ authController.registerUser    │
            │  - validate fields             │
            │  - hash password               │
            │  - save via Mongoose           │
            │  - respond 201                 │
            └────────────────┬───────────────┘
                             │
            ┌────────────────▼───────────────┐
            │ authController.loginUser       │
            │  - validate credentials        │
            │  - compare bcrypt hash         │
            │  - jwt.sign({id,email})        │
            │  - respond with token          │
            └────────────────┬───────────────┘
                             │ token
             ┌───────────────▼──────────────┐
             │ localStorage in browser      │
             └───────────────┬──────────────┘
                             │ Authorization: Bearer <token>
              ┌──────────────▼──────────────┐
              │ GET /api/private/dashboard  │
              └──────────────┬──────────────┘
                             │ verifyToken middleware
              ┌──────────────▼──────────────┐
              │ middleware/authMiddleware   │
              │  - parse header             │
              │  - jwt.verify               │
              │  - attach req.user          │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │ privateRoutes /dashboard    │
              │  - res.json welcome message │
              └─────────────────────────────┘
```

Encourage learners to keep this flow visible; you’ll refer back to each numbered step as the build progresses.

---

### 3. Database & Model (5 min)
Fill in the persistence layer before handling requests.

```js
// server/config/db.js
const mongoose = require('mongoose');

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

```js
// server/models/User.js
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
```

Remind learners:
- Exiting on DB failure prevents the API from serving requests in a broken state.
- The schema enforces unique emails and keeps password hashes out of the response pipeline.

---

### 4. Registration Controller (15 min)
Implement the happy path and all validation branches using the final code as a roadmap:

```js
// server/controllers/authController.js (registerUser)
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
```

Coaching notes:
- Demonstrate the required-field guard and duplicate email branch live (expect 400 responses).
- Emphasize why salt + hash happens server-side (never trust the client).
- Point out that the response excludes the password regardless of request input.

---

### 5. Login & JWT Issuance (15 min)
Switch to the login controller to cover credential verification and token creation.

```js
// server/controllers/authController.js (loginUser)
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

Key talking points:
- Show both failure paths: nonexistent email, incorrect password.
- Explain each `jwt.sign` parameter—payload, secret, expiry—and why the payload stays lean.
- Encourage copy/pasting the token into https://jwt.io to visualize the payload and signature.

---

### 6. Middleware & Protected Route (10 min)
Tie JWT verification to route protection.

```js
// server/middleware/authMiddleware.js
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
```

```js
// server/routes/privateRoutes.js
const express = require('express');
const router = express.Router();
const verifyToken = require('../middleware/authMiddleware');

// Example protected route — only reachable when verifyToken attaches a valid req.user.
router.get('/dashboard', verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}! You have access.` });
});

module.exports = router;
```

Discuss:
- Distinguish 401 (missing token) vs 403 (invalid/expired token).
- Show how middleware-supplied `req.user` personalizes downstream responses.
- Trigger failures by omitting the `Authorization` header or tampering with the token.

#### Protected Route Data Flow
```text
Browser (token in localStorage)
      │
      ├─ GET /api/private/dashboard  ──► Express route stack
      │                                (Authorization: Bearer <token>)
      │
      ▼
verifyToken middleware
      │ 1. Extract token from header
      │ 2. jwt.verify(token, JWT_SECRET)
      │ 3. req.user = decoded payload
      ▼
Route handler
      │ 4. Read req.user.email
      │ 5. Send personalized JSON response
      ▼
Client dashboard displays welcome copy
```

---

### 7. Client Integration (15 min)
Once the server flow works via a REST client, wire the React scaffolding using the completed UI as reference.

1. **Axios Helpers**
   ```js
   // client/src/api/auth.js
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
   - Stress the symmetry between helpers and controller endpoints.
   - Logs mirror server output for easier debugging during the build.

2. **Sign-In Page**
   ```jsx
   // client/src/pages/SignInPage.jsx
   import { useState } from 'react';
   import { useNavigate } from 'react-router-dom';
   import { loginUser, registerUser } from '../api/auth';

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
   - Note how a single form handles both registration and login with a simple mode toggle.
   - When login succeeds, the JWT persists to `localStorage`, setting up the dashboard fetch.

3. **Dashboard**
   ```jsx
   // client/src/pages/Dashboard.jsx
   import { useEffect, useState } from 'react';
   import axios from 'axios';
   import { useNavigate } from 'react-router-dom';

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
   - Emphasize the symmetry between the client’s Authorization header and the server middleware.
   - Demonstrate the error branch by pasting an invalid token into storage.

---

### 8. Validation & Reflection (10 min)
- Pair students to run the full loop: register → login → view dashboard → logout.
- Encourage deliberate breakage (remove token, tamper with payload, change CORS origin) and diagnose responses.
- Compare the newly written `student/` code with the completed `server/` and `client/` versions for self-assessment.

---

## Teaching Tips
- **Surface Logs:** Keep both server and browser consoles open; connect each request/response to the code you just wrote.
- **Security Callouts:** Secrets belong in env variables, JWT payloads stay minimal, and tokens should expire quickly.
- **Stretch Goals:** Add role claims, build a `/api/private/profile` route keyed off `req.user.id`, or experiment with HTTP-only cookies for token storage.

---

## Quick Reference
- Server start: `cd student/server && npm run dev`
- Client start: `cd student/client && npm start`
- Register endpoint: `POST http://localhost:4545/api/auth/register`
- Login endpoint: `POST http://localhost:4545/api/auth/login`
- Protected endpoint: `GET http://localhost:4545/api/private/dashboard`

Use these annotated snippets to narrate the journey from empty scaffolding to a fully authenticated MERN stack, keeping the session interactive and discussion-driven.
