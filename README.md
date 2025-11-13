# Deskrow - Production Deployment Optimized

This project has been optimized for production deployment with separated frontend and backend, designed specifically for deployment on Render.com (backend) and Vercel (frontend):

## Backend (Go Server for Render.com)
- Located in `backend/` directory
- Contains the main Go application optimized for Render.com
- Ready for containerized deployment with Docker
- Uses SQLite databases for data storage
- Provides REST API endpoints for frontend
- CORS configured to allow requests from Vercel deployments
- Production-ready settings (debug disabled, security optimized)

## Frontend (Next.js Application for Vercel)
- Located in `frontend/` directory
- Modern Next.js/React application with TypeScript
- Communicates with backend via API calls
- Optimized for deployment to Vercel
- Includes authentication, dashboard, and transaction management UI

## Render.com Deployment

The backend is pre-configured for seamless deployment to Render.com:
- Dockerfile optimized for Render's container environment
- Render service configuration in `backend/render.yaml`
- Production-ready settings and configurations
- Health check endpoint configured (`/api/v1/server-time`)
- Port configuration to use Render's `$PORT` environment variable

### Backend Deployment (Render.com)
1. Connect your GitHub repository to Render
2. Deploy the `backend/` directory as a Web Service
3. Configure environment variables in Render dashboard (do not use the .env file values directly in production)
4. The service will automatically use Render's `$PORT` variable
5. Configure custom domain if needed

### Frontend Deployment (Vercel)
1. Connect your GitHub repository to Vercel
2. Deploy the `frontend/` directory as a Next.js application
3. Set environment variable NEXT_PUBLIC_API_URL to point to your deployed backend
4. The frontend is configured for static export and can be served from CDN

### API Endpoints
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

### Environment Variables
For frontend deployment, ensure to set:
- NEXT_PUBLIC_API_URL: URL of your deployed backend API (e.g., https://your-app.onrender.com/api/v1)

### Security Considerations
- All sensitive keys and secrets should be configured as secure environment variables in Render
- Never commit real secrets to version control
- Use strong, randomly generated keys for production
- Enable HTTPS for production deployments