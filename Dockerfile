# Use the official Golang image to create a build artifact
FROM golang:1.24-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod files
COPY backend/go.mod backend/go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY backend/ ./

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o server .

# Use a minimal alpine image for the final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create a non-root user
RUN adduser -D -s /bin/sh appuser

# Set the working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/server .

# Note: For API-only backend, we don't need to copy frontend files
# The frontend will be deployed separately to Vercel
# If you want to serve frontend from the same server, uncomment the line below:
# COPY --from=builder --chown=appuser:appuser /app/../../frontend ./frontend

# Create data directory for SQLite databases
RUN mkdir -p data && chown -R appuser:appuser data

# Change ownership of the working directory
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the port (Render will set $PORT environment variable)
EXPOSE $PORT
EXPOSE 3000

# Command to run the executable
# Use $PORT environment variable if available (Render), otherwise default to 3000
CMD ["sh", "-c", "PORT=${PORT:-3000} ./server"]