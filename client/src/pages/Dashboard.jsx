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
