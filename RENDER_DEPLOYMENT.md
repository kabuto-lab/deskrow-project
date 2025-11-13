# Deskrow Deployment on Render.com

This project is optimized for deployment on Render.com.

## Backend Deployment (Go Server on Render)

### Files Required
- All files in the `backend/` directory
- `Dockerfile` for containerized deployment
- Dependencies specified in `go.mod`
- `.env` file with environment variables (configured for production)

### Deployment Steps

1. **Create a new Web Service on Render**
   - Connect to your GitHub repository
   - Set the root directory to `/DESQ3/backend`
   - Render will automatically detect it's a Go service

2. **Configure the build and start commands** (already in render.yaml):
   - Build command: `go build -o server main.go`
   - Start command: `./server`

3. **Set environment variables in Render dashboard**:
   - PORT (provided by Render, do not set manually)
   - SERVER_PORT (fallback if PORT not provided)
   - ENV (should be 'production')
   - DEBUG (should be 'false')
   - All security-related variables (secrets, keys, passwords)
   - Rate limiting settings

4. **Configure health check**:
   - Path: `/api/v1/server-time`

### Render-Specific Configuration

The application is configured to:
- Use Render's `$PORT` environment variable
- Create data directory for SQLite databases
- Run as non-root user for security
- Use production settings by default

### Environment Variables for Render

Required environment variables (set in Render dashboard):
- `ENV=production`
- `DEBUG=false`
- Security keys and secrets (should be set as secure environment variables)
- Database configuration (if needed)

### Port Configuration

The application will:
1. First try to use Render's `$PORT` environment variable
2. Fall back to `SERVER_PORT` if `$PORT` is not available
3. Default to port `3000` if neither is set

### Database Configuration

- SQLite databases will be created in the `data/` directory
- The Dockerfile ensures the `data/` directory exists with proper permissions
- Data will persist as long as the Render instance exists

## Frontend Deployment (Vercel)

### Files Required
- All files in the `frontend/` directory
- Next.js configuration files

### Deployment Steps
1. Create new project on Vercel
2. Point to `/DESQ3/frontend` directory
3. Set environment variable `NEXT_PUBLIC_API_URL` to your Render backend URL
4. Example: `https://your-backend-name.onrender.com/api/v1`

### Environment Variables for Vercel
- `NEXT_PUBLIC_API_URL`: URL of your deployed backend API (e.g., https://your-app.onrender.com/api/v1)

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

## Production Optimizations

- Debug mode is disabled by default
- Production-ready CORS settings
- Optimized for containerized deployment
- Proper health check endpoint configured
- Efficient resource usage for Render's free tier