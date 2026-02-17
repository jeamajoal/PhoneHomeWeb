# PhoneHomeWeb Dockerfile
FROM node:20-alpine

# Create app directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY server.js routes.js logger.js tls.js ./
COPY .env.example .env

# Create necessary directories
RUN mkdir -p /data/uploads \
    /data/logs \
    /data/search \
    /data/user-routes \
    /data/user-scripts \
    /data/user-installers \
    && chown -R node:node /data

# Copy payloads directory
COPY payloads ./payloads

# Copy certs directory structure (but not actual certs, those come from volume)
RUN mkdir -p ./certs && chown -R node:node ./certs

# Switch to non-root user
USER node

# Expose port
EXPOSE 3500

# Start the server
CMD ["node", "server.js"]
