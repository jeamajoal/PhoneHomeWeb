const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const https = require("https");
const crypto = require("crypto");

// Load environment variables from .env (if present)
try {
  require("dotenv").config();
} catch (e) {
  // dotenv is optional at runtime if env vars are supplied by the host
}

const app = express();

// Request logging (JSON lines)
const requestLogDir = path.resolve(__dirname, envStr("REQUEST_LOG_DIR", "logs"));
const requestLogPathRaw = envStr("REQUEST_LOG_PATH", "request_logs.jsonl");

const blockedLogPathRaw = envStr("BLOCKED_LOG_PATH", "blocked.jsonl");

const requestLogPath = path.isAbsolute(requestLogPathRaw)
  ? requestLogPathRaw
  : requestLogPathRaw.includes("/") || requestLogPathRaw.includes("\\")
    ? path.resolve(__dirname, requestLogPathRaw)
    : path.join(requestLogDir, requestLogPathRaw);

const blockedLogPath = path.isAbsolute(blockedLogPathRaw)
  ? blockedLogPathRaw
  : blockedLogPathRaw.includes("/") || blockedLogPathRaw.includes("\\")
    ? path.resolve(__dirname, blockedLogPathRaw)
    : path.join(requestLogDir, blockedLogPathRaw);

try {
  fs.mkdirSync(path.dirname(requestLogPath), { recursive: true });
} catch (err) {
  console.error("Failed to create log directory:", err);
}
let requestLogStream = null;
try {
  requestLogStream = fs.createWriteStream(requestLogPath, { flags: "a" });
  requestLogStream.on("error", (err) => {
    console.error("Request log stream error:", err);
  });
} catch (err) {
  console.error("Failed to open request log stream:", err);
}

let blockedLogStream = null;
let blockedLogDate = null;

function ymd(dateObj) {
  // YYYY-MM-DD in local time
  const y = dateObj.getFullYear();
  const m = String(dateObj.getMonth() + 1).padStart(2, "0");
  const d = String(dateObj.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function datedLogPath(basePath, dateStr) {
  const dir = path.dirname(basePath);
  const ext = path.extname(basePath);
  const name = path.basename(basePath, ext);
  if (ext) return path.join(dir, `${name}-${dateStr}${ext}`);
  return path.join(dir, `${name}-${dateStr}`);
}

function ensureBlockedLogStream() {
  const today = ymd(new Date());
  if (blockedLogStream && blockedLogDate === today && blockedLogStream.writable) {
    return;
  }

  // Rotate: close old stream and open today's file
  try {
    if (blockedLogStream) blockedLogStream.end();
  } catch {
    // ignore
  }

  blockedLogDate = today;
  const todaysPath = datedLogPath(blockedLogPath, today);
  try {
    fs.mkdirSync(path.dirname(todaysPath), { recursive: true });
    blockedLogStream = fs.createWriteStream(todaysPath, { flags: "a" });
    blockedLogStream.on("error", (err) => {
      console.error("Blocked log stream error:", err);
    });
  } catch (err) {
    console.error("Failed to open blocked log stream:", err);
    blockedLogStream = null;
  }
}

try {
  fs.mkdirSync(path.dirname(blockedLogPath), { recursive: true });
  ensureBlockedLogStream();
} catch (err) {
  console.error("Failed to open blocked log stream:", err);
}

function safeJsonLine(obj) {
  try {
    return JSON.stringify(obj);
  } catch {
    return JSON.stringify({ ts: new Date().toISOString(), type: "log_error" });
  }
}

function logRequestEvent(event) {
  const line = safeJsonLine(event) + "\n";
  if (requestLogStream && requestLogStream.writable) {
    requestLogStream.write(line);
  }
}

function logBlockedEvent(event) {
  ensureBlockedLogStream();
  const line = safeJsonLine(event) + "\n";
  if (blockedLogStream && blockedLogStream.writable) {
    blockedLogStream.write(line);
  }
}

process.on("SIGINT", () => {
  if (requestLogStream) requestLogStream.end();
  if (blockedLogStream) blockedLogStream.end();
  process.exit(0);
});
process.on("SIGTERM", () => {
  if (requestLogStream) requestLogStream.end();
  if (blockedLogStream) blockedLogStream.end();
  process.exit(0);
});

function envBool(name, defaultValue = false) {
  const raw = process.env[name];
  if (raw === undefined) return defaultValue;
  return String(raw).toLowerCase() === "true";
}

function envInt(name, defaultValue) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return defaultValue;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) ? value : defaultValue;
}

function envStr(name, defaultValue = "") {
  const raw = process.env[name];
  return raw === undefined ? defaultValue : String(raw);
}

const PORT = envInt("PORT", 3500);
const BIND_HOST = envStr("BIND_HOST", "0.0.0.0");

// Security: Path traversal and filename injection prevention
function sanitizePath(userInput) {
  if (!userInput || typeof userInput !== 'string') {
    throw new Error('Invalid path input');
  }
  
  // LOOP Normalize and remove any leading path traversal
  while (userInput.includes('..') || path.isAbsolute(userInput)) {
    userInput = path.normalize(userInput).replace(/^(\.\.[\/\\])+/, '');
    
    // Reject if still contains path traversal or is absolute
    if (userInput.includes('..') || path.isAbsolute(userInput)) {
      throw new Error('Path traversal attempt detected');
    }
  }
  
  // Reject path separators at start (extra protection)
  if (userInput.startsWith('/') || userInput.startsWith('\\')) {
    throw new Error('Invalid path format');
  }
  
  return userInput;
}

function sanitizeFilename(filename) {
  if (!filename || typeof filename !== 'string') {
    throw new Error('Invalid filename');
  }
  
  // LOOP Remove path separators, control characters, and dangerous characters
  while (/[\/\\:*?"<>|\r\n\x00-\x1f\x7f]/.test(filename)) {
    filename = filename.replace(/[\/\\:*?"<>|\r\n\x00-\x1f\x7f]/g, '_');
  }


  
  // Ensure it's not empty after sanitization
  if (!filename || filename.trim() === '') {
    throw new Error('Invalid filename after sanitization');
  }
  
  // Reject files that are just dots
  if (/^\.+$/.test(filename)) {
    throw new Error('Invalid filename');
  }
  
  return filename;
}

const SERVERURL = envStr("SERVER_URL", `http://localhost:${PORT}`);

// Auth keys for request validation (required)
const STATIC_KEY = envStr("AUTH_KEY", "");
const HT_STATIC_KEY = envStr("AUTH_KEY_HIGH_TRUST", ""); // High-trust key for sensitive operations

if (!STATIC_KEY) {
  console.error("Missing required env var AUTH_KEY. Configure it in .env before starting the server.");
  process.exit(1);
}

// CORS
const corsOriginsRaw = envStr("CORS_ORIGINS", "*");
const corsOrigins = corsOriginsRaw
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (corsOriginsRaw.trim() === "*") {
  app.use(cors());
} else {
  app.use(
    cors({
      origin: corsOrigins,
    })
  );
}

// Security headers to prevent information leakage
app.disable("x-powered-by"); // Hide Express.js
app.use((req, res, next) => {
  res.setHeader("Server", "PhoneHomeWeb"); // Generic server name
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );
  next();
});

// TLS/SSL Configuration following W3Schools TLS documentation
const TLS_CONFIG = {
  // Use strong TLS versions only
  minVersion: "TLSv1.2",
  maxVersion: "TLSv1.3",

  // Configure strong cipher suites
  ciphers: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
  ].join(":"),

  // Security options - disable older TLS versions
  secureOptions:
    crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,

  // Enable perfect forward secrecy
  honorCipherOrder: true,

  // Request client certificate (optional)
  requestCert: false,

  // Don't reject connections without authorized certificates
  rejectUnauthorized: false,
};

// SSL Certificate configuration using proper OpenSSL certificates
let sslOptions = null;
const certsDir = path.resolve(__dirname, envStr("CERTS_DIR", "certs"));

// Certificate filenames must come from env when SSL is enabled
const tlsKeyFile = envStr("TLS_KEY_FILE", "");
const tlsCertFile = envStr("TLS_CERT_FILE", "");
const tlsCaFile = envStr("TLS_CA_FILE", "");
const tlsPfxFile = envStr("TLS_PFX_FILE", "");
const tlsPfxPassphrase = envStr("TLS_PFX_PASSPHRASE", "");

function resolveIfSet(baseDir, fileName) {
  if (!fileName) return null;
  return path.resolve(baseDir, fileName);
}

const keyPath = resolveIfSet(certsDir, tlsKeyFile);
const certPath = resolveIfSet(certsDir, tlsCertFile);
const caPath = resolveIfSet(certsDir, tlsCaFile);
const pfxPath = resolveIfSet(certsDir, tlsPfxFile);

// Check if SSL is disabled via environment variable
const disableSSL = envBool("DISABLE_SSL", false);

if (!disableSSL) {
  // Create certs directory if it doesn't exist
  if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
  }

  const usingPfx = Boolean(tlsPfxFile);
  const usingPemPair = Boolean(tlsKeyFile && tlsCertFile);

  if (!usingPfx && !usingPemPair) {
    console.log("\n" + "=".repeat(80));
    console.log("SSL CONFIG INCOMPLETE");
    console.log("=".repeat(80));
    console.log("SSL is enabled but TLS certificate env vars are not set.");
    console.log("Provide either a PFX bundle or a PEM key+cert pair (or set DISABLE_SSL=true):");
    console.log(`  TLS_PFX_FILE  - ${tlsPfxFile ? "Set" : "Missing"}`);
    console.log(`  TLS_KEY_FILE  - ${tlsKeyFile ? "Set" : "Missing"}`);
    console.log(`  TLS_CERT_FILE - ${tlsCertFile ? "Set" : "Missing"}`);
    console.log("=".repeat(80) + "\n");
    sslOptions = null;
  }

  // Load SSL certificates
  if (sslOptions === null && usingPfx && pfxPath && fs.existsSync(pfxPath)) {
    try {
      sslOptions = {
        ...TLS_CONFIG,
        pfx: fs.readFileSync(pfxPath),
      };

      if (tlsPfxPassphrase) {
        sslOptions.passphrase = tlsPfxPassphrase;
      }

      // Add CA bundle if available (rarely needed with a well-formed PFX, but supported)
      if (caPath && fs.existsSync(caPath)) {
        sslOptions.ca = fs.readFileSync(caPath);
      }

      console.log("\n" + "=".repeat(80));
      console.log("SSL CERTIFICATES LOADED");
      console.log("=".repeat(80));
      console.log(`PFX bundle: ${pfxPath}`);
      console.log(`CA Bundle: ${caPath && fs.existsSync(caPath) ? caPath : "Not found"}`);
      console.log("=".repeat(80) + "\n");
    } catch (error) {
      console.log("\n" + "=".repeat(80));
      console.log("SSL ERROR - Invalid PFX file");
      console.log("=".repeat(80));
      console.error("Error:", error.message);
      console.log("=".repeat(80) + "\n");
      sslOptions = null;
    }
  } else if (
    sslOptions === null &&
    usingPemPair &&
    keyPath &&
    certPath &&
    fs.existsSync(keyPath) &&
    fs.existsSync(certPath)
  ) {
    try {
      // Load CA-issued certificates with TLS configuration
      sslOptions = {
        ...TLS_CONFIG,
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
      };

      // Add CA bundle if available (required for most CA-issued certificates)
      if (caPath && fs.existsSync(caPath)) {
        sslOptions.ca = fs.readFileSync(caPath);
      }

      console.log("\n" + "=".repeat(80));
      console.log("SSL CERTIFICATES LOADED");
      console.log("=".repeat(80));
      console.log(`Private key: ${keyPath}`);
      console.log(`Certificate: ${certPath}`);
      console.log(`CA Bundle: ${caPath && fs.existsSync(caPath) ? caPath : "Not found"}`);
      console.log("=".repeat(80) + "\n");
    } catch (error) {
      console.log("\n" + "=".repeat(80));
      console.log("SSL ERROR - Invalid certificate files");
      console.log("=".repeat(80));
      console.error("Error:", error.message);
      console.log("=".repeat(80) + "\n");
      sslOptions = null;
    }
  } else if (sslOptions === null && (usingPfx || usingPemPair)) {
    console.log("\n" + "=".repeat(80));
    console.log("SSL CERTIFICATES NOT FOUND");
    console.log("=".repeat(80));
    console.log("Missing files:");
    if (usingPfx) {
      console.log(`  ${pfxPath || "(TLS_PFX_FILE not set)"} - ${pfxPath && fs.existsSync(pfxPath) ? "Found" : "Missing"}`);
    }
    if (usingPemPair) {
      console.log(`  ${keyPath || "(TLS_KEY_FILE not set)"} - ${keyPath && fs.existsSync(keyPath) ? "Found" : "Missing"}`);
      console.log(`  ${certPath || "(TLS_CERT_FILE not set)"} - ${certPath && fs.existsSync(certPath) ? "Found" : "Missing"}`);
    }
    console.log("\nAfter receiving your SSL certificate from the CA:");
    console.log(`1. Set TLS_KEY_FILE and save the private key to: ${tlsKeyFile || "<your-key-filename>"}`);
    console.log(`2. Set TLS_CERT_FILE and save the certificate to: ${tlsCertFile || "<your-cert-filename>"}`);
    console.log(`3. Optionally set TLS_CA_FILE and save the CA bundle to: ${tlsCaFile || "<your-ca-bundle-filename>"}`);
    console.log("=".repeat(80) + "\n");
    sslOptions = null;
  }
} else {
  console.log("\n" + "=".repeat(80));
  console.log("SSL DISABLED - Using HTTP mode");
  console.log("=".repeat(80) + "\n");
}

// Storage locations
const uploadsDir = path.resolve(__dirname, envStr("UPLOADS_DIR", "uploads"));
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const payloadsDir = path.resolve(__dirname, envStr("PAYLOADS_DIR", "payloads"));
if (!fs.existsSync(payloadsDir)) {
  fs.mkdirSync(payloadsDir, { recursive: true });
}

// Configure multer for file storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    try {
      // Sanitize the original filename to prevent path traversal
      const sanitized = sanitizeFilename(file.originalname);
      
      // Add timestamp to prevent naming conflicts
      const timestamp = Date.now();
      const ext = path.extname(sanitized);
      const name = path.basename(sanitized, ext);
      cb(null, `${name}-${timestamp}${ext}`);
    } catch (error) {
      console.error('Filename sanitization error:', error.message);
      // Fallback to safe default name
      cb(null, `upload-${Date.now()}.bin`);
    }
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: envInt("MAX_UPLOAD_MB", 500) * 1024 * 1024,
  },
});

// Middleware to parse JSON
app.use(express.json());

// Request logging middleware - structured and non-blocking
app.use((req, res, next) => {
  const ts = new Date().toISOString();
  const startHr = process.hrtime.bigint();
  const requestId = crypto.randomBytes(12).toString("hex");

  req.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);

  const clientIP =
    req.ip || req.connection?.remoteAddress || req.headers["x-forwarded-for"];
  const userAgent = req.get("User-Agent") || "Unknown";
  const contentLength = req.get("Content-Length") || null;

  logRequestEvent({
    ts,
    type: "request_start",
    id: requestId,
    method: req.method,
    url: req.originalUrl || req.url,
    host: req.hostname,
    ip: clientIP,
    ua: userAgent,
    contentLength,
  });

  let loggedEnd = false;
  function logEnd(type) {
    if (loggedEnd) return;
    loggedEnd = true;
    const endHr = process.hrtime.bigint();
    const durationMs = Number(endHr - startHr) / 1e6;
    const resContentLength = res.getHeader("Content-Length") || null;

    logRequestEvent({
      ts: new Date().toISOString(),
      type,
      id: requestId,
      method: req.method,
      url: req.originalUrl || req.url,
      status: res.statusCode,
      durationMs: Math.round(durationMs * 1000) / 1000,
      resContentLength,
    });
  }

  res.on("finish", () => logEnd("request_finish"));
  res.on("close", () => logEnd("request_close"));
  req.on("aborted", () => logEnd("request_aborted"));

  next();
});

// Health endpoint (disabled by default; enable only for troubleshooting)
if (envBool("ENABLE_HEALTH_ENDPOINT", false)) {
  app.get("/api/health", (req, res) => {
    const k = req.get("X-Auth-Key");
    if (k !== STATIC_KEY && k !== HT_STATIC_KEY) {
      // Avoid advertising the endpoint; match the project's "quiet" posture.
      return res.status(404).end();
    }
    res.status(200).json({
      ok: true,
      service: "PhoneHomeWeb",
      time: new Date().toISOString(),
    });
  });
}

// Static key validation middleware - appears unresponsive without key
app.use((req, res, next) => {
  // Allow a single unauthenticated validation path (e.g., CA DCV file)
  const dcvPath = envStr(
    "DCV_VALIDATION_PATH",
    "/.well-known/pki-validation/C6496B1F9978AFBE51D851C02782E3AB.txt"
  );

  // Skip key validation for DCV SSL certificate validation
  if (dcvPath && req.url.endsWith(dcvPath)) {
    const dcvFileName = path.basename(dcvPath);
    res.sendFile(path.join(__dirname, ".well-known", "pki-validation", dcvFileName));
    console.log("=".repeat(80) + "\n");
    return; // Don't call next() - response already sent
  }

  // Check for static key in query parameter or headers
  const keyFromHeader = req.get("X-Auth-Key");
  
  // Set high-trust flag on request object (so endpoints can access it)
  req.isHighTrust = false;
  
  if (keyFromHeader == HT_STATIC_KEY) {
    req.isHighTrust = true;
    console.log(`✓ AUTH: High-trust key provided`);
    console.log("=".repeat(80) + "\n");
    return next();
  }

  if (keyFromHeader == STATIC_KEY) {
    console.log(`✓ AUTH: Valid key provided`);
    console.log("=".repeat(80) + "\n");
    return next();
  }

  // Log unauthorized access attempt but don't respond
  console.log(`✗ BLOCKED: No valid authentication key`);
  console.log("=".repeat(80) + "\n");

  // Dedicated blocked log (JSONL)
  logBlockedEvent({
    ts: new Date().toISOString(),
    type: "blocked",
    id: req.requestId || null,
    method: req.method,
    url: req.originalUrl || req.url,
    host: req.hostname,
    ip: req.ip || req.connection?.remoteAddress || req.headers["x-forwarded-for"],
    ua: req.get("User-Agent") || "Unknown",
    reason: "missing_or_invalid_x_auth_key",
  });

  // Intentionally don't send any response - appears unresponsive
  setTimeout(() => {}, Math.random() * 1000);
  return; // Silent drop
});

// Root endpoint - appears unresponsive (no response sent)
app.get("/", (req, res) => {
  // Log the request but don't send any response - appears unresponsive
  console.log(`⚠ PROBE: Root endpoint accessed (no response sent)`);
  console.log("=".repeat(80) + "\n");
  // Intentionally don't call res.json(), res.send(), or res.end()
});

// Helper function to serve installer files with auth key replacement
// Accepts either a file path (string starting with path) or file content (string)
function serveInstallerWithAuthKey(req, res, filePathOrContent, filename = null) {
  try {
    let fileContent;
    let outputFilename;

    // Check if input is a file path or content string
    if (fs.existsSync(filePathOrContent)) {
      // It's a file path - read the file
      fileContent = fs.readFileSync(filePathOrContent, "utf8");
      outputFilename = filename || path.basename(filePathOrContent);
    } else {
      // It's content string - use directly
      fileContent = filePathOrContent;
      outputFilename = filename || "installer.ps1";
    }

    // Replace all <<AUTHKEY>> placeholders with actual auth key from request header
    const updatedContent = fileContent.replace(
      /<<AUTHKEY>>/g,
      req.get("X-Auth-Key")
    );

    // Set headers for PowerShell file download
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `inline; filename="${outputFilename}"`
    );

    // Send modified content
    res.send(updatedContent);
  } catch (error) {
    console.error("Error serving installer:", error);
    res.status(500).json({
      success: false,
      error: "Error serving installer",
    });
  }
}

function getFileWithParamOverwrite(req, res, paramName, value, filePathOrContent) {
  try {
    let content;
    
    // Check if input is a file path or already content
    if (typeof filePathOrContent === 'string' && fs.existsSync(filePathOrContent)) {
      // It's a file path - read the file
      content = fs.readFileSync(filePathOrContent, "utf8");
    } else if (typeof filePathOrContent === 'string') {
      // It's already content - use directly
      content = filePathOrContent;
    } else {
      throw new Error('Invalid input: must be file path or content string');
    }

    // Replace all <<ParamName>> placeholders with actual value
    // Handle undefined/null values by converting to empty string
    const replacementValue = (value !== undefined && value !== null) ? value : '';
    const updatedContent = content.replace(
      new RegExp(`<<${paramName}>>`, "g"),
      replacementValue
    );

    // Return modified content
    return updatedContent;
  } catch (error) {
    console.error(`Error in getFileWithParamOverwrite for ${paramName}:`, error.message);
    throw error; // Let the caller handle the error
  }
}

// INSTALLERS
// WinPE USB Builder installer endpoint (creates bootable diagnostic USB)
app.get("/winpe-usb-installer", (req, res) => {
  try {
    const installerPath = path.join(
      payloadsDir,
      "WinPECollector",
      "install-winpe-usb-builder.ps1"
    );
    let content = getFileWithParamOverwrite(req, res, "SERVERURL", SERVERURL, installerPath);
    serveInstallerWithAuthKey(req, res, content, "install-winpe-usb-builder.ps1");
  } catch (error) {
    console.error('Error in /winpe-usb-installer:', error.message);
    res.status(500).json({ success: false, error: "Error loading installer" });
  }
});

// WinPE Collector installer endpoint (one-liner deployment)
app.get("/winpecollector-installer", (req, res) => {
  try {
    const installerPath = path.join(
      payloadsDir,
      "WinPECollector",
      "install-winpecollector.ps1"
    );
    let content = getFileWithParamOverwrite(req, res, "SERVERURL", SERVERURL, installerPath);
    serveInstallerWithAuthKey(req, res, content, "install-winpecollector.ps1");
  } catch (error) {
    console.error('Error in /winpecollector-installer:', error.message);
    res.status(500).json({ success: false, error: "Error loading installer" });
  }
});

// FileUpload endpoint
app.get("/fileupload", (req, res) => {
    try {
        const installerPath = path.join(
            payloadsDir,
            "FileUpload",
            "FileUpload.ps1"
        );
        
        // Check if file exists
        if (!fs.existsSync(installerPath)) {
            return res.status(404).json({
                success: false,
                error: "FileUpload.ps1 not found"
            });
        }
        
        // Get file path from header
        const filePath = req.get("X-File-Path");
        if (!filePath) {
            return res.status(400).json({
                success: false,
                error: "X-File-Path header required"
            });
        }
        
        // Replace parameters
        let content = getFileWithParamOverwrite(req, res, "SERVERURL", SERVERURL, installerPath);
        content = getFileWithParamOverwrite(req, res, "FILEPATH", filePath, content);
        serveInstallerWithAuthKey(req, res, content, "FileUpload.ps1");
    } catch (error) {
        console.error('Error in /fileupload endpoint:', error.message);
        res.status(500).json({
            success: false,
            error: "Error preparing file upload script"
        });
    }
});

// WinPe Drivers Repo installer endpoint
app.get("/winpe-drivers", (req, res) => {
    // Return hierarchical list of driver packages organized by manufacturer
    // Structure: WinPeDrivers/HP/[driver-package]/ or WinPeDrivers/HP/network/[vendor]/[package]/
    // Query parameters:
    //   ?manufacturer=HP - filter by manufacturer (top-level folder name)
    //   ?type=network - filter by type (matches any folder name at top level of manufacturer)
    try {
        const driversDir = path.join(payloadsDir, "WinPeDrivers");
        if (!fs.existsSync(driversDir)) {
            return res.status(404).json({
                success: false,
                error: "WinPeDrivers directory not found"
            });
        }

        // Get query parameters
        const manufacturerFilter = req.query.manufacturer ? req.query.manufacturer.toLowerCase() : null;
        const typeFilter = req.query.type ? req.query.type.toLowerCase() : null;

        const drivers = [];
        
        // Recursive function to find all driver packages (folders containing .inf files)
        function findDriverPackages(basePath, relativePath = '') {
            const items = fs.readdirSync(basePath);
            
            // Check if current folder has .inf files (is a driver package)
            const hasInfFiles = items.some(item => item.toLowerCase().endsWith('.inf'));
            
            if (hasInfFiles) {
                // This is a driver package - collect info
                const infFiles = items.filter(item => item.toLowerCase().endsWith('.inf'));
                const allFiles = items.filter(item => {
                    const itemPath = path.join(basePath, item);
                    return fs.statSync(itemPath).isFile();
                });
                
                // Parse path to extract manufacturer and type
                const pathParts = relativePath.split('/');
                const manufacturer = pathParts[0] || '';
                const topLevelFolder = pathParts[1] || '';
                
                // Apply filters
                if (manufacturerFilter && manufacturer.toLowerCase() !== manufacturerFilter) {
                    return; // Skip this driver package
                }
                
                if (typeFilter && !topLevelFolder.toLowerCase().includes(typeFilter)) {
                    return; // Skip this driver package
                }
                
                drivers.push({
                    path: relativePath,
                    name: path.basename(relativePath),
                    manufacturer: manufacturer,
                    topLevelFolder: topLevelFolder,
                    infFiles,
                    totalFiles: allFiles.length,
                    hasSubdirs: items.some(item => {
                        const itemPath = path.join(basePath, item);
                        return fs.statSync(itemPath).isDirectory();
                    })
                });
            }
            
            // Recurse into subdirectories
            const subdirs = items.filter(item => {
                const itemPath = path.join(basePath, item);
                return fs.statSync(itemPath).isDirectory();
            });
            
            for (const subdir of subdirs) {
                const subdirPath = path.join(basePath, subdir);
                const newRelativePath = relativePath ? `${relativePath}/${subdir}` : subdir;
                findDriverPackages(subdirPath, newRelativePath);
            }
        }
        
        // Determine starting path based on manufacturer filter
        let startPath = driversDir;
        let startRelativePath = '';
        
        if (manufacturerFilter) {
            // Find manufacturer folder (case-insensitive)
            const manufacturers = fs.readdirSync(driversDir).filter(item => {
                const itemPath = path.join(driversDir, item);
                return fs.statSync(itemPath).isDirectory();
            });
            
            const matchedManufacturer = manufacturers.find(m => m.toLowerCase() === manufacturerFilter);
            
            if (matchedManufacturer) {
                startPath = path.join(driversDir, matchedManufacturer);
                startRelativePath = matchedManufacturer;
            } else {
                // No matching manufacturer found
                return res.json({
                    success: true,
                    count: 0,
                    drivers: [],
                    filters: { manufacturer: manufacturerFilter, type: typeFilter }
                });
            }
        }
        
        // Start recursive search
        findDriverPackages(startPath, startRelativePath);

        res.json({
            success: true,
            count: drivers.length,
            drivers: drivers.sort((a, b) => a.path.localeCompare(b.path)),
            filters: { manufacturer: manufacturerFilter, type: typeFilter }
        });
    } catch (error) {
        console.error('Error in /winpe-drivers endpoint:', error.message);
        res.status(500).json({
            success: false,
            error: "Error retrieving WinPE drivers"
        });
    }
});

// File upload endpoint
app.post("/upload", upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "No file uploaded",
      });
    }

    const fileInfo = {
      success: true,
      savedAs: req.file.filename,
      size: req.file.size,
      uploadedAt: new Date().toISOString(),
    };

    console.log("=".repeat(80));
    console.log(`  ✓ UPLOAD SUCCESS:`);
    console.log(`    Original: ${req.file.originalname}`);
    console.log(`    Saved As: ${req.file.filename}`);
    console.log(`    Size: ${(req.file.size / 1024 / 1024).toFixed(2)} MB`);
    console.log("=".repeat(80) + "\n");

    res.json(fileInfo);
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error during upload",
    });
  }
});

// List uploaded files endpoint - restricted information
app.get("/uploads", (req, res) => {
     // requires high trust authkey
    if (req.isHighTrust !== true) {
        console.log(`✗ BLOCKED: Download requires high-trust authentication key`);
        console.log("=".repeat(80) + "\n");
        return res.status(403).json({
            success: false,
            error: "High-trust authentication key required"
        });
    }
  try {
    const files = fs.readdirSync(uploadsDir).map((filename) => {
      const filePath = path.join(uploadsDir, filename);
      const stats = fs.statSync(filePath);
      return {
        filename,
        size: stats.size,
        uploadedAt: stats.birthtime.toISOString().split("T")[0], // Date only, no time
      };
    });

    res.json({
      success: true,
      count: files.length,
      files,
    });
  } catch (error) {
    console.error("Error listing files:", error);
    res.status(500).json({
      success: false,
      error: "Unable to list files",
    });
  }
});

// List available payloads
app.get("/payloads", (req, res) => {
  try {
    const payloadsDir = path.join(__dirname, "payloads");
    if (!fs.existsSync(payloadsDir)) {
      return res.status(404).json({
        success: false,
        error: "Payloads directory not found",
      });
    }

    const folders = fs.readdirSync(payloadsDir).filter((file) => {
      return fs.statSync(path.join(payloadsDir, file)).isDirectory();
    });

    const payloads = folders.map((folder) => {
      const configPath = path.join(payloadsDir, folder, "config.json");
      if (fs.existsSync(configPath)) {
        try {
          const configContent = fs.readFileSync(configPath, "utf-8");
          
          // Limit JSON size to prevent DoS attacks (1MB max)
          if (configContent.length > 1024 * 1024) {
            throw new Error('Config file too large');
          }
          
          const config = JSON.parse(configContent);
          
          // Type validation to prevent prototype pollution
          if (typeof config !== 'object' || config === null || Array.isArray(config)) {
            throw new Error('Invalid config structure');
          }
          
          return {
            folder,
            name: config.name || folder,
            version: config.version || "unknown",
            description: config.description || "",
            endpoint: config.endpoint || "",
            params: config.parameters || [],
          };
        } catch (err) {
          console.error(`Error reading config for payload ${folder}:`, err.message);
          return {
            folder,
            name: folder,
            version: "unknown",
            description: "",
            endpoint: "",
          };
        }
      } else {
        return {
          folder,
          name: folder,
          version: "unknown",
          description: "",
          endpoint: "",
        };
      }
    });

    res.json({
      success: true,
      count: payloads.length,
      payloads,
    });
  } catch (error) {
    console.error("Error listing payloads:", error);
    res.status(500).json({
      success: false,
      error: "Unable to list payloads",
    });
  }
});

// Download payload files
app.get("/payloads/:folder/download/:filename", (req, res) => {
    try {
        // Sanitize inputs to prevent path traversal
        const folder = sanitizePath(req.params.folder);
        const filename = sanitizePath(req.params.filename);
        const filePath = path.join(payloadsDir, folder, filename);
        
        // Verify the resolved path is still within payloadsDir
        const resolvedPath = path.resolve(filePath);
        const resolvedPayloadsDir = path.resolve(payloadsDir);
        if (!resolvedPath.startsWith(resolvedPayloadsDir)) {
            console.log(`✗ BLOCKED: Path traversal attempt detected: ${req.params.folder}/${req.params.filename}`);
            return res.status(403).json({
                success: false,
                error: "Access denied"
            });
        }

        if (fs.existsSync(filePath)) {
          const ext = path.extname(filename).toLowerCase();
          const textExts = new Set([
            ".ps1",
            ".psm1",
            ".psd1",
            ".json",
            ".txt",
            ".md",
            ".cmd",
            ".bat",
            ".sh",
          ]);

          // IMPORTANT: Never run placeholder replacement on binary files (e.g., .zip)
          // because reading as UTF-8 and rewriting will corrupt the file.
          if (!textExts.has(ext)) {
            res.setHeader(
              "Content-Disposition",
              `attachment; filename="${path.basename(filename)}"`
            );
            return res.sendFile(resolvedPath);
          }

          let content = getFileWithParamOverwrite(
            req,
            res,
            "SERVERURL",
            SERVERURL,
            filePath
          );
          content = getFileWithParamOverwrite(
            req,
            res,
            "FILEPATH",
            filePath,
            content
          );
          serveInstallerWithAuthKey(req, res, content, filePath);
        } else {
          res.status(404).json({
            success: false,
            error: "Payload file not found",
          });
        }
    } catch (error) {
        console.error('Path sanitization error:', error.message);
        res.status(400).json({
            success: false,
            error: "Invalid path parameters"
        });
    }
});

// Download Specific Uploaded file
app.get("/download", (req, res) => {
    // requires high trust authkey
    if (req.isHighTrust !== true) {
        console.log(`✗ BLOCKED: Download requires high-trust authentication key`);
        console.log("=".repeat(80) + "\n");
        return res.status(403).json({
            success: false,
            error: "High-trust authentication key required"
        });
    }
    // Require filename in header
    if (!req.get("X-Filename")) {
        return res.status(400).json({
            success: false,
            error: "X-Filename header required"
        });
    }
    const filenameHeader = req.get("X-Filename");
  try {
    console.log(`  ✓ DOWNLOAD REQUEST for file: ${filenameHeader}`);
    // Sanitize filename to prevent path traversal - filename cannot contain path separators
    const filename = sanitizePath(filenameHeader);
    console.log(`  ✓ SANITIZED FILENAME: ${filename}`);
    const filePath = path.join(uploadsDir, filename);
    
    // Verify the resolved path is still within uploadsDir
    const resolvedPath = path.resolve(filePath);
    const resolvedUploadsDir = path.resolve(uploadsDir);
    if (!resolvedPath.startsWith(resolvedUploadsDir)) {
        console.log(`✗ BLOCKED: Path traversal attempt detected: ${filenameHeader}`);
        return res.status(403).json({
            success: false,
            error: "Access denied"
        });
    }
    
    if (fs.existsSync(filePath)) {
      // Sanitize filename for Content-Disposition header (prevent header injection)
      const safeFilename = sanitizeFilename(path.basename(filename));
      
      // Set up abort handler before starting download
      let downloadAborted = false;
      
      req.on('close', () => {
        if (!res.writableEnded) {
          downloadAborted = true;
          console.log(`⚠ DOWNLOAD ABORTED by client: ${safeFilename}`);
        }
      });
      
      req.on('error', (err) => {
        downloadAborted = true;
        console.error(`⚠ DOWNLOAD ERROR (client): ${safeFilename}:`, err.message);
      });
      
      try {
        const fileStream = fs.createReadStream(filePath);
        
        fileStream.on('error', (err) => {
          console.error(`⚠ FILE STREAM ERROR: ${safeFilename}:`, err.message);
          if (!res.headersSent) {
            res.status(500).json({
              success: false,
              error: "Error reading file"
            });
          }
        });
        
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Content-Disposition", `attachment; filename="${safeFilename}"`);
        res.setHeader("Content-Length", fs.statSync(filePath).size);
        
        // Pipe the file to response
        fileStream.pipe(res);
        
        fileStream.on('end', () => {
          if (!downloadAborted) {
            console.log(`✓ DOWNLOAD COMPLETED: ${safeFilename}`);
          }
        });
        
      } catch (err) {
        console.error(`⚠ DOWNLOAD SETUP ERROR: ${safeFilename}:`, err.message);
        if (!res.headersSent) {
          res.status(500).json({
            success: false,
            error: "Error starting download"
          });
        }
      }
    } else {
      res.status(404).json({
        success: false,
        error: "File not found",
      });
    }
  } catch (error) {
    console.error('Path sanitization error:', error.message);
    res.status(400).json({
        success: false,
        error: "Invalid filename parameter"
    });
  }
});

// Error handling middleware - prevent information leakage
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        error: "File size limit exceeded",
      });
    }
    return res.status(400).json({
      success: false,
      error: "Upload error",
    });
  }

  // Log full error details server-side only
  console.error("Server error:", error);

  // Return generic error to client
  res.status(500).json({
    success: false,
    error: "Internal server error",
  });
});

// Start the server (HTTPS if certificates available, otherwise HTTP)
if (sslOptions) {
  https.createServer(sslOptions, app).listen(PORT, BIND_HOST, () => {
    console.log("\n" + "=".repeat(80));
    console.log("SERVER STARTED - HTTPS MODE");
    console.log("=".repeat(80));
    console.log(`Port: ${PORT}`);
    console.log(`Listening: ${BIND_HOST}`);
    console.log(`Started: ${new Date().toISOString()}`);
    console.log("=".repeat(80));
    console.log("Waiting for requests...\n");
  });
} else {
  app.listen(PORT, BIND_HOST, () => {
    console.log("\n" + "=".repeat(80));
    console.log("SERVER STARTED - HTTP MODE");
    console.log("=".repeat(80));
    console.log(`Port: ${PORT}`);
    console.log(`Listening: ${BIND_HOST}`);
    console.log(`Started: ${new Date().toISOString()}`);
    console.log("=".repeat(80));
    console.log("Waiting for requests...\n");
  });
}


