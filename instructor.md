# MERN JWT Integration Session (Instructor Guide)

## Overview
This session is a **guided teardown and rebuild of the JWT layer** inside an existing MERN project. Learners already have a running Express API and React client; your role is to help them trace how tokens are issued, verified, and consumed. The lesson fits a 60‑minute block with an additional 15 minutes reserved for experimentation and Q&A.

### Learning Outcomes
- Explain the end-to-end authentication handshake across MERN components.
- Demonstrate secure password handling with bcrypt and short-lived JWTs.
- Diagnose common auth failures (CORS, invalid signatures, missing headers).
- Implement small enhancements such as role claims or logout flows.

### Prerequisites
- MongoDB reachable locally (or Atlas cluster) and Node 16 installed.
- Students comfortable with async/await, ES modules/CommonJS, and React hooks.
- Repo cloned, `.env` copied from `.env.example`, and both `server` and `client` dependencies installed.

---

## Session Blueprint

1. **Orientation & Warm-Up (5 min)**
   - Show the project tree (`client/`, `server/`) and highlight logging instrumentation.
   - Run both apps (`npm run dev`, `npm start`) to prove the baseline works.
   - Set expectations: focus on JWT internals, not general Express/React setup.

2. **Server-Side Deep Dive (15 min)**
   - Walk through `server/server.js`:
     - CORS options (`CLIENT_ORIGIN`) and why preflight matters.
     - Request logging middleware — demonstrate how payloads surface in the console.
   - Cover `config/db.js`, `models/User.js` briefly (emphasize schema uniqueness and hashed password storage).
   - Live-navigate `controllers/authController.js`:
     - Stop on each comment block (salt generation, duplicate checks, `jwt.sign` payload).
     - Trigger duplicate registration to read the 400 branch in real time.
   - Discuss `middleware/authMiddleware.js` and `routes/privateRoutes.js` — point out the 401 vs 403 branches and how `req.user` is passed downstream.

3. **Client-Side Consumption (15 min)**
   - Inspect `client/src/api/auth.js`, focusing on the `API_BASE_URL` override and logging output.
   - Step through `SignInPage.jsx`: state management, registration toggle, token storage.
   - Visit `Dashboard.jsx`: highlight Authorization header construction and graceful handling when the token is missing or invalid.
   - Encourage students to watch both browser and server consoles during a login to connect the dots.

   **Visualization Aid:** Draw the two pipelines on a whiteboard (mirrors the student guide):
   - *Registration* – React form → Axios helper → `/api/auth/register` → controller hashes password → Mongo persistence → success response (no token stored).
   - *Login* – React form → Axios helper → `/api/auth/login` → controller verifies password → `jwt.sign` returns token → localStorage → dashboard fetch with `Authorization` header → middleware verifies → protected response.

4. **Guided Experiments (15 min)**
   - **Token Tamper Drill:** Modify the JWT in localStorage, refresh, and analyze the middleware response.
   - **CORS Swap:** Temporarily change `CLIENT_ORIGIN` to provoke a preflight failure, then restore.
   - **Role Claim Stretch:** Add a `role` field to the registration payload, persist it, emit it in `jwt.sign`, and display it on the dashboard. Use this to discuss authorization vs. authentication.

5. **Debrief & Next Steps (10 min)**
   - Facilitate a “round robin” where each student cites one failure mode and how to address it.
   - Suggest homework: build refresh tokens, tighten error messaging, or add server-side logout logic.

---

## Coaching Notes
- **Logging as a teaching tool:** Both controllers and client helpers emit payload/response data. Pause after each major request so learners correlate what they see in DevTools with the Node console.
- **Security callouts:** Reinforce why secrets belong in environment variables, why JWT payloads must stay minimal, and the impact of token expiry.
- **Troubleshooting checklist:**
  - 401 → missing `Authorization` header or truncated `Bearer` prefix.
  - 403 → signature mismatch / expired token (`jwt.verify` branch).
  - CORS error → mismatched `CLIENT_ORIGIN` or server not responding to OPTIONS.
  - Mongo duplicate → surface `11000` error and review the duplicate guard.
- **Clarify persistence:** Tokens are never stored in MongoDB—only hashed passwords are. Encourage learners to articulate where the JWT resides (client localStorage) after login.
- **Differentiation:** Advanced learners can explore rotating secrets, adding refresh tokens, or building role-based guards; others can reinforce fundamentals by writing integration tests or Postman collections.

---

## Assessment Strategy

### Formative Checks
- Cold-call: “Walk me through what happens after `loginUser` resolves on the client.”
- Partner exercise: Have pairs annotate the `jwt.sign` call with their own comments before comparing to the provided ones.
- Quick quiz: Present sample headers and ask which will pass the middleware.

### Exit Criteria
- Students reproduce a successful register/login/dashboard cycle while narrating key steps.
- They can deliberately trigger and resolve a CORS or invalid-token error.
- They propose at least one enhancement or mitigation for JWT-based auth.

### Optional Extensions
- Build a `/api/private/profile` route returning data from Mongo tied to `req.user.id`.
- Swap in HTTP-only cookies and contrast pros/cons with localStorage.
- Add rate limiting or account lockouts after repeated failed logins.

---

## Reference Material
- Express: https://expressjs.com/
- Mongoose: https://mongoosejs.com/
- jsonwebtoken: https://github.com/auth0/node-jsonwebtoken
- React Router 6: https://reactrouter.com/en/main/start/tutorial
- Security refresher: OWASP JSON Web Token Cheat Sheet – https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html
