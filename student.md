# MERN JWT Integration Workshop (Student Guide)

Welcome to the focused JWT module for our MERN stack. The repository already includes a functional Express API and React client — your goal in this session is to **understand, validate, and extend the JWT authentication flow** that glues them together. Follow the checkpoints below, keep an eye on the console logs we added for visibility, and be prepared to explain each step to your peers.

---

## 1. What You Start With

- Node 16 environment, MongoDB running locally.
- Complete project structure:
  - `server/` – Express app with auth routes, controllers, middleware, and Mongoose model.
  - `client/` – React app with pages for sign-in and dashboard, plus Axios helpers.
- Prewritten code already issues and consumes JWTs. Your job is to trace how and why it works.

> **Tip:** Have two terminals ready — one for the API (`server/`) and another for the React app (`client/`). Keep both consoles visible so you can read the logging hooks we use for teaching.

---

## 2. Launch the Stack

```bash
# Terminal 1
cd server
npm install
npm run dev

# Terminal 2
cd client
npm install
npm start
```

Confirm:
- API logs `🚀 Server running on port 4545` and `✅ MongoDB Connected`.
- React dev server opens at `http://localhost:3000`.

If you change ports, update `server/.env` (`PORT`, `CLIENT_ORIGIN`) and `client/.env` (`REACT_APP_API_BASE_URL`) accordingly.

---

## 3. Map the JWT Lifecycle

Study this request/response path before diving into code:

1. **Registration** (`POST /api/auth/register`)  
   Client sends credentials → server hashes password → new user stored → confirmation returned.
2. **Login** (`POST /api/auth/login`)  
   Client sends email + password → server verifies hash → server signs JWT → token returned.
3. **Protected access** (`GET /api/private/dashboard`)  
   Client includes `Authorization: Bearer <token>` header → middleware verifies token → controller returns protected payload.

Keep this sequence in mind when you inspect each file.

---

## 4. Server-Side Walkthrough

### 4.1 Environment & Config
- File: `server/.env`  
  ```
  PORT=4545
  MONGO_URI=mongodb://127.0.0.1:27017/jwtauth
  JWT_SECRET=supersecretkey123
  CLIENT_ORIGIN=http://localhost:3000
  ```
  - `JWT_SECRET` is the private key for signing tokens — rotate it outside of training.
  - `CLIENT_ORIGIN` drives CORS; mismatched origins surface as preflight errors.

- File: `server/server.js`  
  Key sections to review:
  ```js
  const corsOptions = {
    origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  };

  app.use(cors(corsOptions));
  app.options('*', cors(corsOptions));
  app.use(express.json());

  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`, req.body || {});
    next();
  });
  ```
  - **Why it matters:** CORS ensures the React app can make authenticated requests, and the logging middleware exposes every request body in your terminal for debugging.

### 4.2 Database & Model
- File: `server/config/db.js`  
  Async connection with failure handling. Pay special attention to the `process.exit(1)` call — this prevents the server from running without a database.
- File: `server/models/User.js`  
  ```js
  const userSchema = new mongoose.Schema(
    {
      username: { type: String, required: true },
      email: { type: String, required: true, unique: true },
      password: { type: String, required: true }
    },
    { timestamps: true }
  );
  ```
  - Email uniqueness is enforced at the schema level; watch for duplicate key errors when testing registration.

### 4.3 Auth Controller
- File: `server/controllers/authController.js`
  ```js
  exports.registerUser = async (req, res) => {
    const { username, email, password } = req.body;
    console.log('↩️  Incoming register payload:', { username, email });
    ...
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = await User.create({ username, email, password: hashedPassword });
    const response = {
      message: '✅ User registered',
      user: { id: newUser._id, username: newUser.username, email: newUser.email }
    };
    console.log('✅ Register response:', response);
    res.status(201).json(response);
  };
  ```
  - **Checkpoint:** Try registering twice with the same email. Observe the 400 response and the log output.

  ```js
  exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    console.log('↩️  Incoming login payload:', { email });
    ...
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    const response = { message: '✅ Login successful', token, user: { ... } };
    console.log('✅ Login response:', response);
    res.json(response);
  };
  ```
  - **Checkpoint:** Intentionally submit a wrong password and locate the logged error path.

### 4.4 Middleware
- File: `server/middleware/authMiddleware.js`
  ```js
  function verifyToken(req, res, next) {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided.' });

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch {
      res.status(403).json({ message: 'Invalid token.' });
    }
  }
  ```
  - **Checkpoint:** Remove the `Bearer` prefix in the client (temporarily) and note the 401 response.

### 4.5 Routes
- File: `server/routes/authRoutes.js` – binds controller functions to `/register` and `/login`.
- File: `server/routes/privateRoutes.js` – protects `/dashboard` via `verifyToken`.
- Both routes are mounted in `server/server.js` under `/api/auth` and `/api/private` respectively.

---

## 5. Visualizing the Data Flow

Use these diagrams to narrate what happens during registration and login. Read them top to bottom, left to right.

### 5.1 Registration Path (Form ➜ MongoDB)
```
[React SignInPage] --(username, email, password)--> [loginUser/registerUser helper]
        |
        v
[Axios POST /api/auth/register] -- JSON body --> [Express route /register]
        |
        v
[authController.registerUser]
    • validates required fields
    • checks Mongo for existing email
    • hashes password with bcrypt
        |
        v
[Mongoose User.create] -- hashed password stored --> [MongoDB jwtauth.users]
        |
        v
[Controller response] -- 201 + user summary --> [Axios promise resolves]
        |
        v
[React UI] -- alert success --> prompt learner to sign in
```
- Only the **hashed password** is persisted. No tokens are saved to the database during registration.
- Server console logs show the incoming payload (username/email only) and the sanitized response.

### 5.2 Login Path (Form ➜ JWT ➜ Protected Route)
```
[React SignInPage] --(email, password)--> [loginUser helper]
        |
        v
[Axios POST /api/auth/login] --> [Express route /login]
        |
        v
[authController.loginUser]
    • fetches user by email from Mongo
    • bcrypt.compare verifies password vs hashed value
    • jwt.sign({id, email}, secret, 1h)
        |
        v
[Controller response] -- token + user payload --> [Axios resolves]
        |
        v
[React UI]
    • stores token in localStorage
    • navigate('/dashboard')
        |
        v
[Dashboard.jsx useEffect]
    • reads token from localStorage
    • Axios GET /api/private/dashboard with Authorization header
        |
        v
[verifyToken middleware]
    • splits Bearer header, jwt.verify token
    • attaches decoded payload to req.user
        |
        v
[Route handler] -- personalized message --> [React dashboard renders text]
```
- The token **lives in the browser** (localStorage). MongoDB never stores the JWT itself.
- If you mutate or remove the token, the middleware will emit `401/403` and the dashboard shows the access-denied message.

---

## 6. Client-Side Walkthrough

### 5.1 Axios Helpers
- File: `client/src/api/auth.js`
  ```js
  const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:4545';

  export const loginUser = async (email, password) => {
    const payload = { email, password };
    console.log('➡️  Login request:', payload);
    const res = await axios.post(`${API_BASE_URL}/api/auth/login`, payload);
    console.log('⬅️  Login response:', res.data);
    return res.data;
  };
  ```
  - **Checkpoint:** Toggle the network tab in DevTools, verify the request URL, payload, and status codes.

### 5.2 Sign-In Page
- File: `client/src/pages/SignInPage.jsx`
  - Tracks form state, toggles between registration and sign-in modes, and calls the appropriate helper.
  - Saves `data.token` to `localStorage` and redirects to `/dashboard`.
  - Console logs show the user flow (e.g., form submissions, token storage).
  - **Exercise:** Add basic form validation (e.g., minimum password length) and display UI hints.

### 5.3 Dashboard
- File: `client/src/pages/Dashboard.jsx`
  ```js
  const token = localStorage.getItem('token');
  if (!token) {
    setMessage('Please log in first.');
    return;
  }

  const res = await axios.get(`${API_BASE_URL}/api/private/dashboard`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  ```
  - Includes a logout button that clears the token and navigates back to `/`.
  - **Checkpoint:** Expire the token manually (change it in localStorage) and confirm the middleware returns `Access denied`.

---

## 7. Hands-On Tasks

1. **Trace a full login cycle:**  
   Open the browser console and both terminal windows. Submit the sign-in form and narrate the request/responses as they appear in the logs.

2. **Break and fix CORS:**  
   Change `CLIENT_ORIGIN` to a mismatched value, restart the server, and observe the browser error. Restore the correct value.

3. **Token tampering experiment:**  
   Copy the JWT from localStorage, paste it into https://jwt.io, modify the payload (e.g., change the email), paste it back into localStorage, and reload the dashboard. Explain why the request fails.

4. **Add a registration form field:**  
   Extend `SignInPage.jsx` to capture a `role` field and persist it on the server (update the Mongoose schema, controller, and token payload accordingly).

---

## 8. Debugging Checklist

- **401 Unauthorized:** Check for missing `Authorization` header or truncated `Bearer` prefix.
- **403 Forbidden:** Token signature invalid or expired — inspect server logs for `Invalid token`.
- **CORS / preflight errors:** Ensure `CLIENT_ORIGIN` matches the React dev server URL and the API is reachable (`curl http://localhost:4545/api/auth/login`).
- **Duplicate registration:** Look for Mongo error code `11000`, then verify the controller’s duplicate email guard.
- **Silent client failures:** Review console output from `auth.js`, `SignInPage.jsx`, and `Dashboard.jsx` — every request logs both the payload and response.

---

## 9. Deliverables

By the end of the session you should be able to:
- Describe the purpose of `jwt.sign` vs. `jwt.verify`.
- Diagram the complete auth flow from browser form to protected resource.
- Demonstrate handling of both success and error cases in the UI.
- Propose at least one improvement (e.g., refresh tokens, server-side session revocation).

Document what you observed and any modifications you made — we will discuss your findings in the next review circle.
