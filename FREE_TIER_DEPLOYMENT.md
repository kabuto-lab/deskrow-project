# Deploying Deskrow on Render.com Free Tier

This guide provides instructions for deploying the Deskrow application on Render's free tier.

## Free Tier Limitations

Before deploying, be aware of Render's free tier limitations:
- Service will sleep after 15 minutes of inactivity
- 100 build minutes per month
- 750 hours of runtime per month
- 1 GB of disk storage
- Limited bandwidth

## Backend Deployment (Go Server)

### Preparing for Deployment

The backend is already optimized for Render deployment with:
- Dockerfile configured for containerized deployment
- render.yaml configuration file
- Production-ready settings
- Health check endpoint at `/api/v1/server-time`

### Deployment Steps

1. **Push your code to GitHub**
   - Make sure the DESQ3/backend directory contains your Go code
   - Verify the Dockerfile and render.yaml are in the correct location

2. **Create a new Web Service on Render**
   - Log into your Render dashboard
   - Click "New +" → "Web Service"
   - Connect to your GitHub repository
   - Choose your repository containing the Deskrow code

3. **Configure the deployment**
   - Environment: Go
   - Build Root: Set to `/DESQ3/backend`
   - Build Command: Will be detected from render.yaml
   - Start Command: Will be detected from render.yaml

4. **Set environment variables**
   - PORT (provided by Render, do not set manually)
   - ENV=production
   - DEBUG=false
   - All security secrets (use Render's secret environment variables feature)
   - Do not commit actual secret values to your repository

5. **Deploy**
   - The service will build and deploy automatically
   - Monitor the build logs for any errors

### Render Service Configuration

The provided `render.yaml` includes:
- Auto-deployment from GitHub
- Health check path (`/api/v1/server-time`)
- Production environment settings
- Port configuration for Render's environment

### Optimizations for Free Tier

To work well within Render's free tier constraints:

1. **Minimize build size**: The Dockerfile is optimized for size
2. **Health check**: The `/api/v1/server-time` endpoint serves as a health check
3. **Sleep/wake cycle**: Be aware services will sleep after inactivity

## Frontend Deployment (Vercel)

1. **Connect to Vercel**
   - Create a new project on Vercel
   - Link to your GitHub repository
   - Set root directory to `/DESQ3/frontend`

2. **Environment variables**
   - Set `NEXT_PUBLIC_API_URL` to your Render backend URL
   - Example: `https://your-backend-name.onrender.com/api/v1`

## Environment Variables for Production

### Required Variables (Render Dashboard)
- PORT (provided automatically)
- ENV=production
- DEBUG=false

### Security Variables (Set as Secrets)
- SESSION_SECRET (must be a strong, randomly generated string)
- CSRF_SECRET (must be a strong, randomly generated string)
- ENCRYPTION_ROOT_SEED (must be a strong, randomly generated string)
- ADMIN_SHARED_SECRET (must be a strong, randomly generated string)
- All other sensitive keys and passwords

## Managing the Free Tier Limitations

### To Keep Your Service Active
- Consider having a monitoring service make periodic requests to `/api/v1/server-time` to keep the service from sleeping
- Or accept that initial requests after sleep will be slow (cold start)

### Monitoring Usage
- Track your build minutes and runtime hours in the Render dashboard
- Optimize build processes to stay within limits

## Testing the Deployment

After deployment:
1. Visit your Render backend URL `/api/v1/server-time` to confirm it's running
2. Test API endpoints to ensure functionality
3. Connect your frontend to the backend

## Troubleshooting

If your service fails to deploy:
1. Check the build logs in your Render dashboard
2. Verify all environment variables are set correctly
3. Ensure the Dockerfile and render.yaml are in the correct directory
4. Confirm all dependencies are properly specified in go.mod

## Security Best Practices

For production deployment:
- Generate strong, unique secrets for production
- Never commit actual secrets to version control
- Use Render's encrypted environment variables for sensitive data
- Regularly rotate security keys
- Enable custom domains with HTTPS for production use