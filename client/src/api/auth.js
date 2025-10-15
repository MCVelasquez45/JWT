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
