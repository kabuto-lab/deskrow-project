// app/error.tsx
'use client';

import { useEffect } from 'react';

export default function Error({
  error,
  reset,
}: {
  error: Error;
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service
    console.error(error);
  }, [error]);

  return (
    <div className="error-container">
      <h2>Something went wrong!</h2>
      <p>{error.message}</p>
      <button
        onClick={
          () => {
            // Attempt to recover by trying to re-render the segment
            reset();
          }
        }
      >
        Try again
      </button>
      
      <style>{`
        .error-container {
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          height: 100vh;
          text-align: center;
          padding: 2rem;
        }

        h2 {
          margin-bottom: 1rem;
        }

        p {
          margin-bottom: 1rem;
          color: #e00;
        }

        button {
          padding: 0.5rem 1rem;
          background: #0070f3;
          color: white;
          border: none;
          border-radius: 5px;
          cursor: pointer;
        }
      `}</style>
    </div>
  );
}