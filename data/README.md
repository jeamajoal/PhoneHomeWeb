# PhoneHomeWeb Data Directory

This directory contains persistent data and user-customizable content for PhoneHomeWeb.

## Directory Structure

### `/data/user-routes/`
Contains custom route definitions that are dynamically loaded by the server.

- **Purpose**: Extend the server with custom endpoints without modifying core code
- **Security**: Routes defined here are protected by the same authentication middleware as core routes
- **File**: `index.js` - Main entry point for user routes (see example template)

### `/data/user-scripts/`
Public scripts directory accessible without authentication.

- **Purpose**: Host scripts that users can download and execute from their devices without needing an auth key
- **Security**: ⚠️ **NO AUTHENTICATION REQUIRED** - Files here are publicly accessible via `/user-scripts/:filename`
- **Use Case**: Phone home scripts that devices can fetch and run automatically

### `/data/user-installers/`
Protected installers directory requiring authentication.

- **Purpose**: Host installer scripts and packages that require authentication
- **Security**: ✅ **AUTH KEY REQUIRED** - Files here require valid `X-Auth-Key` header via `/user-installers/:filename`
- **Use Case**: Sensitive installers or scripts that should only be accessed by authorized users

### `/data/search/`
Search data directory for indexing and search functionality.

- **Purpose**: Store search indexes or searchable data
- **Security**: Protected by standard authentication
- **Use Case**: Future search functionality expansion

## Usage Examples

### Adding a User Route

Edit `/data/user-routes/index.js`:

```javascript
module.exports = function registerUserRoutes(app, deps) {
  app.get("/custom/status", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });
};
```

### Adding a Public Script

Place your script in `/data/user-scripts/`:

```bash
# Create a public script
echo '#!/bin/bash
curl -X POST https://your-server:3500/upload \
  -H "X-Auth-Key: YOUR_KEY" \
  -F "file=@/tmp/data.zip"' > /data/user-scripts/phone-home.sh
chmod +x /data/user-scripts/phone-home.sh
```

Access it without auth:
```bash
curl http://your-server:3500/user-scripts/phone-home.sh
```

### Adding a Protected Installer

Place your installer in `/data/user-installers/`:

```bash
cp my-app-installer.exe /data/user-installers/
```

Access it with auth:
```powershell
Invoke-WebRequest -Uri "https://your-server:3500/user-installers/my-app-installer.exe" `
  -Headers @{"X-Auth-Key"="your-auth-key"} `
  -OutFile "installer.exe"
```

## Docker Volume Mapping

In docker-compose.yaml, these directories are mapped as:

```yaml
volumes:
  - ./data/user-routes:/data/user-routes:ro      # Read-only
  - ./data/user-scripts:/data/user-scripts:ro    # Read-only
  - ./data/user-installers:/data/user-installers:ro  # Read-only
  - ./data/search:/data/search                   # Read-write
```

## Security Notes

1. **user-scripts** is the ONLY directory accessible without authentication
2. All other endpoints require valid `X-Auth-Key` header
3. User routes inherit the same authentication middleware as core routes
4. Always review scripts before placing them in `user-scripts/` directory
5. Use `user-installers/` for any sensitive files that should require authentication
