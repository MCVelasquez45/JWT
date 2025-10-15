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
