// app/page.tsx
'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiClient } from './lib/api';

export default function Home() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const router = useRouter();

  useEffect(() => {
    // Check if user is logged in by checking for session token
    const token = localStorage.getItem('deskrow_token');
    setIsLoggedIn(!!token);
  }, []);

  const handleLogout = async () => {
    try {
      await apiClient.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('deskrow_token');
      localStorage.removeItem('deskrow_user');
      setIsLoggedIn(false);
      router.push('/');
    }
  };

  return (
    <div className="container">
      <header>
        <nav>
          <div className="logo">Deskrow</div>
          <div className="nav-links">
            {isLoggedIn ? (
              <>
                <Link href="/app">Dashboard</Link>
                <button onClick={handleLogout}>Logout</button>
              </>
            ) : (
              <>
                <Link href="/auth">Sign In</Link>
                <Link href="/auth?mode=signup">Sign Up</Link>
              </>
            )}
          </div>
        </nav>
      </header>

      <main>
        <section className="hero">
          <h1>Secure Transaction Management</h1>
          <p>Experience the next generation of secure, decentralized transaction processing with end-to-end encryption.</p>
          {!isLoggedIn && (
            <div className="cta-buttons">
              <Link href="/auth?mode=signup" className="btn-primary">Get Started</Link>
              <Link href="/auth" className="btn-secondary">Sign In</Link>
            </div>
          )}
        </section>

        <section className="features">
          <div className="feature">
            <h3>End-to-End Encryption</h3>
            <p>Your data is encrypted at all times, ensuring maximum privacy and security.</p>
          </div>
          <div className="feature">
            <h3>Decentralized Identity</h3>
            <p>Create and manage your digital identity without relying on centralized authorities.</p>
          </div>
          <div className="feature">
            <h3>Real-time Monitoring</h3>
            <p>Track your transactions with our real-time dashboard and analytics.</p>
          </div>
        </section>
      </main>

      <footer>
        <p>© {new Date().getFullYear()} Deskrow. All rights reserved.</p>
      </footer>

      <style jsx>{`
        .container {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
        }
        
        header {
          padding: 1rem 2rem;
          border-bottom: 1px solid #eaeaea;
        }
        
        nav {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .logo {
          font-size: 1.5rem;
          font-weight: bold;
        }
        
        .nav-links {
          display: flex;
          gap: 1rem;
          align-items: center;
        }
        
        .nav-links a, .nav-links button {
          text-decoration: none;
          padding: 0.5rem 1rem;
          border-radius: 5px;
          border: none;
          background: #f0f0f0;
          cursor: pointer;
        }
        
        .hero {
          padding: 4rem 2rem;
          text-align: center;
          flex: 1;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
        }
        
        .hero h1 {
          font-size: 3rem;
          margin-bottom: 1rem;
        }
        
        .hero p {
          font-size: 1.2rem;
          margin-bottom: 2rem;
          max-width: 600px;
        }
        
        .cta-buttons {
          display: flex;
          gap: 1rem;
        }
        
        .btn-primary {
          background: #0070f3;
          color: white;
          padding: 0.75rem 1.5rem;
          border-radius: 8px;
          text-decoration: none;
        }
        
        .btn-secondary {
          background: #f0f0f0;
          color: #333;
          padding: 0.75rem 1.5rem;
          border-radius: 8px;
          text-decoration: none;
        }
        
        .features {
          display: flex;
          justify-content: space-around;
          padding: 4rem 2rem;
          flex-wrap: wrap;
          gap: 2rem;
        }
        
        .feature {
          max-width: 300px;
          text-align: center;
        }
        
        footer {
          padding: 2rem;
          text-align: center;
          border-top: 1px solid #eaeaea;
          margin-top: auto;
        }
      `}</style>
    </div>
  );
}