// app/auth/page.tsx
'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { apiClient } from '../lib/api';

export default function Auth() {
  const [isSignup, setIsSignup] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    alias: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const mode = searchParams.get('mode');
    if (mode === 'signup') {
      setIsSignup(true);
    }
  }, [searchParams]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isSignup) {
        if (formData.password !== formData.confirmPassword) {
          setError('Passwords do not match');
          setLoading(false);
          return;
        }

        const result = await apiClient.signup(formData.username, formData.password, formData.alias);
        if (result.success) {
          // Store user info and redirect
          localStorage.setItem('deskrow_token', result.token || '');
          localStorage.setItem('deskrow_user', JSON.stringify({ alias: formData.alias }));
          router.push('/app');
        } else {
          setError(result.detail || 'Signup failed');
        }
      } else {
        const result = await apiClient.login(formData.username, formData.password);
        if (result.success) {
          // Store user info and redirect
          localStorage.setItem('deskrow_token', result.token || '');
          localStorage.setItem('deskrow_user', JSON.stringify({ alias: result.userAlias }));
          router.push(result.redirect || '/app');
        } else {
          setError(result.detail || 'Login failed');
        }
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred. Please try again.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-form">
        <h2>{isSignup ? 'Create Account' : 'Sign In'}</h2>
        
        {error && <div className="error">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          {isSignup && (
            <div className="form-group">
              <label htmlFor="alias">Display Name</label>
              <input
                type="text"
                id="alias"
                name="alias"
                value={formData.alias}
                onChange={handleChange}
                required
              />
            </div>
          )}
          
          <div className="form-group">
            <label htmlFor="username">{isSignup ? 'Username' : 'Username or Email'}</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
            />
          </div>
          
          {isSignup && (
            <div className="form-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <input
                type="password"
                id="confirmPassword"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
              />
            </div>
          )}
          
          <button type="submit" disabled={loading} className="submit-btn">
            {loading ? 'Processing...' : (isSignup ? 'Sign Up' : 'Sign In')}
          </button>
        </form>
        
        <div className="auth-switch">
          <p>
            {isSignup ? 'Already have an account?' : 'Need an account?'}{' '}
            <button 
              onClick={() => setIsSignup(!isSignup)}
              className="switch-btn"
            >
              {isSignup ? 'Sign In' : 'Sign Up'}
            </button>
          </p>
        </div>
      </div>

      <style>{`
        .auth-container {
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          padding: 1rem;
        }

        .auth-form {
          width: 100%;
          max-width: 400px;
          padding: 2rem;
          border: 1px solid #eaeaea;
          border-radius: 10px;
          background: white;
        }

        h2 {
          text-align: center;
          margin-bottom: 1.5rem;
        }

        .form-group {
          margin-bottom: 1rem;
        }

        label {
          display: block;
          margin-bottom: 0.5rem;
          font-weight: 500;
        }

        input {
          width: 100%;
          padding: 0.75rem;
          border: 1px solid #ddd;
          border-radius: 5px;
          font-size: 1rem;
        }

        input:focus {
          outline: none;
          border-color: #0070f3;
        }

        .submit-btn {
          width: 100%;
          padding: 0.75rem;
          background: #0070f3;
          color: white;
          border: none;
          border-radius: 5px;
          font-size: 1rem;
          cursor: pointer;
        }

        .submit-btn:disabled {
          background: #ccc;
          cursor: not-allowed;
        }

        .auth-switch {
          margin-top: 1.5rem;
          text-align: center;
        }

        .switch-btn {
          background: none;
          border: none;
          color: #0070f3;
          text-decoration: underline;
          cursor: pointer;
          padding: 0;
          font-size: 1rem;
        }

        .error {
          color: #e00;
          padding: 0.5rem;
          margin-bottom: 1rem;
          background: #ffe0e0;
          border-radius: 5px;
          text-align: center;
        }
      `}</style>
    </div>
  );
}