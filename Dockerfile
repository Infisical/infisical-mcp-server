# Use multi-stage build for optimal production image
FROM node:lts-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including dev dependencies for build)
RUN npm ci --ignore-scripts

# Copy source code
COPY . .

# Build the application (both stdio and HTTP servers)
RUN npm run build

# Production stage
FROM node:lts-alpine AS production

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev --ignore-scripts

# Copy built artifacts from builder stage
COPY --from=builder /app/dist ./dist

# Set environment variables
ENV NODE_ENV=production

# Expose port for HTTP server
EXPOSE 3333

# Add health check - test the main endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3333/', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))" || echo "HTTP server not running"

# Default to HTTP server for container usage, but allow override
ENTRYPOINT ["node", "dist/flowmcp-server.js"]

# Alternative for stdio usage (can be overridden)
# CMD ["node", "dist/index.js"]