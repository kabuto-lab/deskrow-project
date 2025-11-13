// app/app/page.tsx
'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { apiClient } from '../lib/api';

export default function App() {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('deskrow_token');
    if (!token) {
      router.push('/auth');
      return;
    }

    // In a real app, fetch user details from the API
    // For now, we'll just assume the user is valid
    const storedUser = localStorage.getItem('deskrow_user');
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    } else {
      // Default user object
      setUser({ alias: 'User', id: 1 });
    }

    setLoading(false);
  }, [router]);

  const handleLogout = async () => {
    try {
      await apiClient.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('deskrow_token');
      localStorage.removeItem('deskrow_user');
      router.push('/');
    }
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div className="app-container">
      <header>
        <nav>
          <div className="logo">Deskrow</div>
          <div className="nav-links">
            <Link href="/app">Dashboard</Link>
            <Link href="/app/transactions">Transactions</Link>
            <span>Welcome, {user?.alias || 'User'}</span>
            <button onClick={handleLogout} className="logout-btn">Logout</button>
          </div>
        </nav>
      </header>

      <main className="main-content">
        <div className="dashboard">
          <h1>Dashboard</h1>
          <p>Welcome to your secure transaction dashboard.</p>
          
          <div className="dashboard-cards">
            <div className="card">
              <h3>Total Transactions</h3>
              <p>0</p>
            </div>
            <div className="card">
              <h3>Active Connections</h3>
              <p>0</p>
            </div>
            <div className="card">
              <h3>Security Status</h3>
              <p>Active</p>
            </div>
          </div>
        </div>
      </main>

      <style jsx>{`
        .app-container {
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
          gap: 1.5rem;
          align-items: center;
        }
        
        .nav-links a {
          text-decoration: none;
          color: #333;
        }
        
        .logout-btn {
          background: #f0f0f0;
          border: none;
          padding: 0.5rem 1rem;
          border-radius: 5px;
          cursor: pointer;
        }
        
        .main-content {
          flex: 1;
          padding: 2rem;
        }
        
        .dashboard h1 {
          margin-bottom: 1rem;
        }
        
        .dashboard-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 1.5rem;
          margin-top: 2rem;
        }
        
        .card {
          padding: 1.5rem;
          border: 1px solid #eaeaea;
          border-radius: 8px;
          text-align: center;
        }
        
        .card h3 {
          margin-bottom: 0.5rem;
        }
        
        .card p {
          font-size: 1.5rem;
          font-weight: bold;
        }
        
        .loading {
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
        }
      `}</style>
    </div>
  );
}