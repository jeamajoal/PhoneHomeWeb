# PhoneHomeWeb Docker Deployment Guide

This guide covers deploying PhoneHomeWeb using Docker and Docker Compose.

## Prerequisites

- Docker Engine 20.10 or higher
- Docker Compose 2.0 or higher
- Access to clone the repository or download the source

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/jeamajoal/PhoneHomeWeb.git
cd PhoneHomeWeb
```

### 2. Configure Environment Variables

Create a `.env` file in the project root with your configuration:

```bash
cp .env.example .env
nano .env  # or your preferred editor
```

**Required settings:**

```env
# Authentication keys (REQUIRED)
AUTH_KEY=your-secure-random-key-here
AUTH_KEY_HIGH_TRUST=your-high-trust-key-here

# Server URL (update with your actual domain/IP)
SERVER_URL=http://your-server:3500

# Optional: TLS/HTTPS configuration
DISABLE_SSL=true
```

**Generate secure authentication keys:**

```bash
# Using OpenSSL
openssl rand -hex 32

# Or Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Build and Start

```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

### 4. Access the Server

The server will be available at `http://localhost:3500` (or your configured `SERVER_URL`).

Test the connection:

```bash
curl -H "X-Auth-Key: your-auth-key" http://localhost:3500/api/health
```

## Directory Structure

The Docker setup uses the following directory structure:

```
PhoneHomeWeb/
├── docker-compose.yaml      # Docker Compose configuration
├── Dockerfile               # Container image definition
├── .env                     # Environment variables (create from .env.example)
├── data/                    # Data volume (persistent storage)
│   ├── user-routes/         # Custom route definitions
│   │   └── index.js         # User routes entry point
│   ├── user-scripts/        # Public scripts (NO AUTH required)
│   │   ├── example-phone-home.sh
│   │   └── example-phone-home.ps1
│   ├── user-installers/     # Protected installers (AUTH required)
│   │   └── example-installer.ps1
│   └── search/              # Search data (future use)
└── certs/                   # TLS certificates (for HTTPS)
```

## Data Volume Configuration

### User Routes (`/data/user-routes/`)

Add custom routes to extend the server functionality:

**Example: Custom Status Endpoint**

Edit `data/user-routes/index.js`:

```javascript
module.exports = function registerUserRoutes(app, deps) {
  app.get("/custom/status", (req, res) => {
    res.json({ 
      status: "ok", 
      timestamp: new Date().toISOString(),
      custom: true
    });
  });
  
  console.log("[INFO] Custom routes registered");
};
```

Restart the container to load new routes:

```bash
docker-compose restart
```

### User Scripts (`/data/user-scripts/`)

⚠️ **PUBLIC ACCESS - NO AUTHENTICATION REQUIRED**

Place scripts here that users/devices can download without authentication:

```bash
# Create a public phone-home script
cat > data/user-scripts/phone-home.sh << 'EOF'
#!/bin/bash
# Auto-collected system info uploader
# Users can run: curl http://server:3500/user-scripts/phone-home.sh | bash

SERVER_URL="http://your-server:3500"
AUTH_KEY="<<AUTHKEY>>"  # Will be replaced at runtime

# Collect and upload diagnostics
tar -czf /tmp/diagnostics.tar.gz /var/log
curl -X POST "$SERVER_URL/upload" \
  -H "X-Auth-Key: $AUTH_KEY" \
  -F "file=@/tmp/diagnostics.tar.gz"
EOF

chmod +x data/user-scripts/phone-home.sh
```

**Access without authentication:**

```bash
curl http://your-server:3500/user-scripts/phone-home.sh | bash
```

### User Installers (`/data/user-installers/`)

✅ **AUTHENTICATION REQUIRED**

Place installers and sensitive scripts here:

```bash
# Add a protected installer
cp my-application-installer.exe data/user-installers/

# Access requires authentication
curl -H "X-Auth-Key: your-key" \
  http://your-server:3500/user-installers/my-application-installer.exe \
  -o installer.exe
```

**PowerShell example:**

```powershell
Invoke-WebRequest `
  -Uri "http://your-server:3500/user-installers/installer.ps1" `
  -Headers @{"X-Auth-Key"="your-auth-key"} `
  -OutFile "installer.ps1"
```

## HTTPS/TLS Configuration

### Using Let's Encrypt

1. Obtain certificates using Certbot:

```bash
sudo certbot certonly --standalone -d your-domain.com
```

2. Copy certificates to the certs directory:

```bash
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem certs/
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem certs/
sudo chown $USER:$USER certs/*.pem
```

3. Update `.env`:

```env
DISABLE_SSL=false
SERVER_URL=https://your-domain.com:3500
TLS_KEY_FILE=privkey.pem
TLS_CERT_FILE=fullchain.pem
```

4. Restart the container:

```bash
docker-compose down
docker-compose up -d
```

### Using Self-Signed Certificates

For testing or internal networks:

```bash
cd certs

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem \
  -days 365 -nodes -subj "/CN=your-server-hostname"
```

Update `.env`:

```env
DISABLE_SSL=false
TLS_KEY_FILE=server-key.pem
TLS_CERT_FILE=server-cert.pem
```

## Docker Compose Configuration

### Environment Variables

All environment variables from `.env` are passed to the container. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3500` | Server port |
| `SERVER_URL` | `http://localhost:3500` | Public URL for clients |
| `AUTH_KEY` | *(required)* | Standard authentication key |
| `AUTH_KEY_HIGH_TRUST` | *(optional)* | High-trust operations key |
| `MAX_UPLOAD_MB` | `500` | Maximum upload size (MB) |
| `DISABLE_SSL` | `true` | Set to `false` for HTTPS |

### Volume Mounts

```yaml
volumes:
  # Persistent data volume
  - phonehomeweb-data:/data
  
  # TLS certificates (read-only)
  - ./certs:/app/certs:ro
  
  # User customization directories (read-only)
  - ./data/user-routes:/data/user-routes:ro
  - ./data/user-scripts:/data/user-scripts:ro
  - ./data/user-installers:/data/user-installers:ro
  
  # Search data (read-write for future expansion)
  - ./data/search:/data/search
```

### Network Configuration

The container exposes port 3500 by default. To use a different port:

```bash
# Option 1: Update .env
PORT=8080

# Option 2: Update docker-compose.yaml
ports:
  - "8080:3500"
```

## Advanced Configuration

### Running Behind a Reverse Proxy

Example Nginx configuration:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:3500;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Large file upload support
        client_max_body_size 500M;
        proxy_read_timeout 300s;
    }
}
```

### Persistent Storage

The `phonehomeweb-data` volume stores:

- Uploaded files (`/data/uploads`)
- Request logs (`/data/logs`)
- Search data (`/data/search`)

To backup the volume:

```bash
# Create backup
docker run --rm \
  -v phonehomeweb-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/phonehomeweb-backup.tar.gz /data

# Restore backup
docker run --rm \
  -v phonehomeweb-data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/phonehomeweb-backup.tar.gz -C /
```

### Health Checks

The container includes a health check that verifies the server is responding:

```bash
# Check container health
docker-compose ps

# View health check logs
docker inspect phonehomeweb --format='{{.State.Health.Status}}'
```

## Troubleshooting

### Container Won't Start

```bash
# View detailed logs
docker-compose logs

# Check if port is already in use
sudo netstat -tlnp | grep 3500

# Verify .env file exists and has required variables
cat .env | grep AUTH_KEY
```

### Permission Issues

```bash
# Ensure data directories have correct permissions
sudo chown -R $USER:$USER data/
chmod -R 755 data/

# For certificates
sudo chown -R $USER:$USER certs/
chmod 600 certs/*.pem
```

### Cannot Access Server

```bash
# Check if container is running
docker-compose ps

# Test from inside the container
docker exec phonehomeweb wget -q -O- http://localhost:3500 || echo "Server not responding"

# Check firewall
sudo ufw status
sudo ufw allow 3500/tcp
```

### Authentication Issues

```bash
# Enable debug logging
echo "DEBUG_AUTH=true" >> .env
docker-compose restart

# View auth debug logs
docker-compose logs -f | grep "DEBUG AUTH"
```

## Updating

### Update the Application

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Update Dependencies

```bash
# Rebuild the image with updated dependencies
docker-compose build --no-cache
docker-compose up -d
```

## Security Best Practices

1. **Use HTTPS in production** - Never run without TLS on public networks
2. **Rotate auth keys regularly** - Especially after each use or incident
3. **Limit network exposure** - Use firewall rules to restrict access
4. **Monitor logs** - Review `/data/logs/blocked.jsonl` for unauthorized attempts
5. **Keep images updated** - Regularly rebuild with `docker-compose build`
6. **Backup data volume** - Regular backups of `phonehomeweb-data`
7. **Restrict user-scripts** - Only place trusted scripts in public directory

## Support

For issues, questions, or contributions:

- GitHub: https://github.com/jeamajoal/PhoneHomeWeb
- Documentation: See README.md in the repository
