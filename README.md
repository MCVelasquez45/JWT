## MERN JWT Authentication (Client/Server Layout)

This repository ships with a complete JWT-authenticated MERN stack configured for Node 16. The project is split into `server/` (Express + MongoDB) and `client/` (React 18 + React Router 6).

### Quick Start
- `cd server && npm install && npm run dev`
- `cd client && npm install && npm start`

Create a `.env` in `server/` (one is provided with sample values) and ensure MongoDB is running locally before starting the server. By default the API listens on `PORT=4545`; update the React client base URL via `REACT_APP_API_BASE_URL` if you change it. Keep `CLIENT_ORIGIN` aligned with your React dev server URL (defaults to `http://localhost:3000`).

### Tech Stack
- Express 4.17.1, Mongoose 6.0.11, bcryptjs, jsonwebtoken
- React 18.2, React Router DOM 6.4.2, Axios 1.1.2, Bootstrap 5

See `student.md` for a detailed build-along guide and `instructor.md` for teaching notes.
