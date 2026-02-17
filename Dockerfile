# PhoneHomeWeb Dockerfile
FROM node:20-alpine

# Create app directory
WORKDIR /app

# Copy package files and pre-built dependencies
# Note: We copy node_modules from the host because npm ci/install fails
# in some Alpine environments. This is acceptable for this use case since
# the app has no native dependencies that are platform-specific.
COPY package*.json ./
COPY node_modules ./node_modules

# Copy application code
COPY server.js routes.js logger.js tls.js ./
COPY .env.example .env

# Copy payloads directory
COPY payloads ./payloads

# Create necessary directories
RUN mkdir -p /data/uploads \
    /data/logs \
    /data/search \
    /data/user-routes \
    /data/user-scripts \
    /data/user-installers \
    ./certs

# Fix permissions
RUN chown -R node:node /app /data

# Switch to non-root user
USER node

# Expose port
EXPOSE 3500

# Start the server
CMD ["node", "server.js"]
