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
