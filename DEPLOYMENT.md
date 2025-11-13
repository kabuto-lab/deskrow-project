# Production Deployment Instructions for Deskrow

## Overview
This project is optimized for production deployment with separated frontend and backend:
- Frontend (Next.js app): Deployed on Vercel
- Backend (Go API server): Deployed on Render.com (containerized with Docker)

The application is configured for production with security and performance optimizations.

## Backend Deployment (Render.com)

### Files Required
- All files in the `backend/` directory
- `Dockerfile` for containerized deployment
- Dependencies specified in `go.mod`
- `render.yaml` for service configuration

### Deployment Steps
1. Create a new Web Service on Render.com
2. Connect to your GitHub repository
3. Set the root directory to `/DESQ3/backend`
4. Render will use the provided Dockerfile for containerized deployment
5. Configure environment variables in Render dashboard (IMPORTANT: Do not use .env values directly in production)
6. The service will automatically use Render's $PORT environment variable
7. Health check path is configured as `/api/v1/server-time`

### Render Service Configuration
The `render.yaml` file configures:
- Service name: deskrow-backend
- Environment: Go with Docker
- Health check endpoint
- Production settings
- Auto-deploy from GitHub

### Environment Variables (Production)
Configure these environment variables in your Render dashboard:
- PORT (provided automatically by Render)
- ENV=production
- DEBUG=false
- All security-related variables (secrets, keys, passwords) - configure as secret environment variables
- Rate limiting and security settings

### Production Optimizations
- Debug mode disabled (DEBUG=false)
- Production CORS settings
- Health check endpoint available
- Optimized for Render's container environment

## Frontend Deployment (Vercel)

### Files Required
- All files in the `frontend/` directory
- Next.js configuration files (next.config.js, package.json, etc.)

### Environment Variables
Before deploying to Vercel, set:
- NEXT_PUBLIC_API_URL: Full URL of your deployed backend API (e.g., https://your-app-name.onrender.com/api/v1)

### Deployment Steps
1. Push your code to a GitHub repository
2. Connect Vercel to your GitHub repository
3. Set the root directory to `/DESQ3/frontend`
4. Add the environment variable NEXT_PUBLIC_API_URL
5. Vercel will automatically detect it's a Next.js project and build accordingly

## API Endpoints

The backend provides the following API endpoints:
- GET /api/v1/server-time - Health check endpoint
- POST /api/v1/auth/signin - User login
- POST /api/v1/auth/signup - User registration
- POST /api/v1/auth/signout - User logout
- POST /api/v1/auth/check-username - Check username availability
- POST /api/v1/auth/wallet - Wallet authentication
- POST /api/v1/identity/generate - Generate user identity
- POST /api/v1/transactions - Create transaction
- GET /api/v1/transactions/{hash} - Get transaction by hash

## Security Considerations

For production deployment:
- Never use the default secrets from the .env file in production
- Generate strong, unique secrets for production environment
- Use Render's secure environment variables for sensitive data
- Regularly rotate security keys
- Enable HTTPS with custom domains for production

## Containerized Deployment

The Dockerfile is optimized for Render.com deployment:
- Uses multi-stage build to minimize image size
- Runs as non-root user for security
- Creates data directory for SQLite databases
- Configures to use Render's $PORT environment variable
- Includes production-ready startup command