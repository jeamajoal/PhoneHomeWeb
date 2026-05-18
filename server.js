"use strict";

const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const https = require("https");
const http = require("http");
const crypto = require("crypto");

// Load environment variables from .env (if present)
try {
  require("dotenv").config();
} catch (e) {
  // dotenv is optional at runtime if env vars are supplied by the host
}

// Environment variable helpers (must be defined before first use below)
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
  if (raw === undefined) return defaultValue;
  let val = String(raw).trim();
  // dotenv strips surrounding double-quotes but not single-quotes;
  // strip them here so AUTH_KEY='secret' works the same as AUTH_KEY=secret.
  if (val.length >= 2 && val.startsWith("'") && val.endsWith("'")) {
    val = val.slice(1, -1);
  }
  return val;
}

const app = express();

// Structured request & blocked-request logging (extracted to logger.js)
const { logRequestEvent, logBlockedEvent, shutdown: shutdownLogger } = require("./logger")({
  baseDir: __dirname,
  envStr,
});

process.on("SIGINT", () => {
  shutdownLogger();
  process.exit(0);
});
process.on("SIGTERM", () => {
  shutdownLogger();
  process.exit(0);
});

const PORT = envInt("PORT", 3500);
const BIND_HOST = envStr("BIND_HOST", "0.0.0.0");

// Separate non-SSL HTTP listener used only for DCV validation files.
// Set DCV_HTTP_PORT=80 if Node is allowed to bind port 80, otherwise use
// a higher port and forward/proxy port 80 to it.
const DCV_HTTP_PORT = envInt("DCV_HTTP_PORT", 80);
const DCV_HTTP_BIND_HOST = envStr("DCV_HTTP_BIND_HOST", BIND_HOST);

// Security: Path traversal and filename injection prevention
function sanitizePath(userInput) {
  if (!userInput || typeof userInput !== "string") {
    throw new Error("Invalid path input");
  }

  // Normalize and strip any path traversal sequences (limit iterations to prevent abuse)
  let sanitizeIter = 0;
  while (userInput.includes("..") || path.isAbsolute(userInput)) {
    if (++sanitizeIter > 5) {
      throw new Error("Path traversal attempt detected");
    }
    userInput = path.normalize(userInput).replace(/^(\.\.[/\\])+/, "");

    // Reject if still contains path traversal or is absolute
    if (userInput.includes("..") || path.isAbsolute(userInput)) {
      throw new Error("Path traversal attempt detected");
    }
  }

  // Reject path separators at start (extra protection)
  if (userInput.startsWith("/") || userInput.startsWith("\\")) {
    throw new Error("Invalid path format");
  }

  return userInput;
}

function sanitizeFilename(filename) {
  if (!filename || typeof filename !== "string") {
    throw new Error("Invalid filename");
  }

  // Remove path separators, control characters, and dangerous characters
  filename = filename.replace(/[\/\\:*?"<>|\r\n\x00-\x1f\x7f]/g, "_");

  // Ensure it's not empty after sanitization
  if (!filename || filename.trim() === "") {
    throw new Error("Invalid filename after sanitization");
  }

  // Reject files that are just dots
  if (/^\.+$/.test(filename)) {
    throw new Error("Invalid filename");
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

// Log key lengths at startup so operators can spot truncation, extra
// whitespace, or quote-wrapping issues without leaking the actual values.
console.log(`AUTH_KEY loaded (length: ${STATIC_KEY.length})`);
if (HT_STATIC_KEY) {
  console.log(`AUTH_KEY_HIGH_TRUST loaded (length: ${HT_STATIC_KEY.length})`);
} else {
  console.log("AUTH_KEY_HIGH_TRUST not configured (high-trust endpoints disabled)");
}

// Timing-safe key comparison to prevent timing attacks.
// Returns false when either value is empty, which also guards against
// matching an unconfigured HT_STATIC_KEY ("") with an empty header.
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length === 0 || b.length === 0) return false;
  try {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
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
  // X-XSS-Protection "1" is deprecated and can introduce vulnerabilities in
  // some browsers.  "0" disables it; rely on Content-Security-Policy instead.
  res.setHeader("X-XSS-Protection", "0");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );
  // HSTS: tell browsers to always use HTTPS (checked at request time so the
  // header is only sent when the server is actually running with TLS).
  if (req.secure || req.headers["x-forwarded-proto"] === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// TLS/SSL configuration (extracted to tls.js)
const sslOptions = require("./tls")({ baseDir: __dirname, envStr, envBool });

// Storage locations
const uploadsDir = path.resolve(__dirname, envStr("UPLOADS_DIR", "uploads"));
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const payloadsDir = path.resolve(__dirname, envStr("PAYLOADS_DIR", "payloads"));
if (!fs.existsSync(payloadsDir)) {
  fs.mkdirSync(payloadsDir, { recursive: true });
}

const publicUnknownDir = path.resolve(__dirname, "pub", "unknown");
if (!fs.existsSync(publicUnknownDir)) {
  fs.mkdirSync(publicUnknownDir, { recursive: true });
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
      console.error("Filename sanitization error:", error.message);
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

// Middleware to parse JSON (file uploads go through multer, not this parser)
app.use(express.json({ limit: "1mb" }));

// Request logging middleware - structured and non-blocking
app.use((req, res, next) => {
  const ts = new Date().toISOString();
  const startHr = process.hrtime.bigint();
  const requestId = crypto.randomBytes(12).toString("hex");

  req.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);

  const clientIP =
    req.ip || req.socket?.remoteAddress || req.headers["x-forwarded-for"];
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
    if (!safeEqual(k, STATIC_KEY) && !safeEqual(k, HT_STATIC_KEY)) {
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

function isPathInside(childPath, parentPath) {
  const relative = path.relative(parentPath, childPath);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function serveDcvValidationFile(req, res, options = {}) {
  const silentNotFound = options.silentNotFound ?? true;

  // DCV_VALIDATION_PATH must be an absolute URL path/folder such as:
  //   /.well-known/pki-validation/                 (Sectigo HTTP DCV)
  //   /.well-known/acme-challenge/                 (Let's Encrypt)
  // Files matching that prefix are served from <project>/<dcvPath>.
  const dcvPath = envStr("DCV_VALIDATION_PATH", "");

  if (!dcvPath) {
    return false;
  }

  if (!dcvPath.startsWith("/")) {
    console.log("[X] DCV: DCV_VALIDATION_PATH must start with /");
    if (!silentNotFound) res.status(500).end();
    return true;
  }

  // Extract pathname only; strips query params to prevent bypass tricks.
  const requestPath = new URL(req.url, "http://localhost").pathname;

  // Ensure dcvPath ends with / for proper prefix matching.
  const dcvFolder = dcvPath.endsWith("/") ? dcvPath : dcvPath + "/";

  if (!requestPath.startsWith(dcvFolder)) {
    return false;
  }

  const projectRoot = path.resolve(__dirname);
  const dcvDiskFolder = path.resolve(projectRoot, dcvFolder.replace(/^\/+/, ""));
  const dcvDiskPath = path.resolve(projectRoot, requestPath.replace(/^\/+/, ""));

  // Check both project root and DCV folder boundaries.
  if (!isPathInside(dcvDiskPath, projectRoot) || !isPathInside(dcvDiskPath, dcvDiskFolder)) {
    console.log(`[X] DCV: Path traversal blocked for ${requestPath}`);
    console.log("=".repeat(80) + "\n");
    if (!silentNotFound) res.status(404).end();
    return true;
  }

  try {
    if (!fs.existsSync(dcvDiskPath)) {
      console.log(`[X] DCV: File not found on disk: ${dcvDiskPath}`);
      console.log("=".repeat(80) + "\n");
      if (!silentNotFound) res.status(404).end();
      return true;
    }

    // Additional check: ensure it's a file, not a directory.
    if (!fs.statSync(dcvDiskPath).isFile()) {
      console.log(`[X] DCV: Path is not a file: ${dcvDiskPath}`);
      console.log("=".repeat(80) + "\n");
      if (!silentNotFound) res.status(404).end();
      return true;
    }

    console.log(`[OK] DCV: Serving validation file ${dcvDiskPath}`);
    console.log("=".repeat(80) + "\n");
    res.sendFile(dcvDiskPath);
    return true;
  } catch (err) {
    console.log(`[X] DCV: Error serving file: ${err.message}`);
    console.log("=".repeat(80) + "\n");
    if (!silentNotFound) res.status(500).end();
    return true;
  }
}

function servePublicUnknownFile(req, res, options = {}) {
  const silentNotFound = options.silentNotFound ?? false;

  // Public path intended for openly hosted HTTPS content.
  const publicRootPath = "/pub/unknown";

  // Extract pathname only; strips query params to prevent bypass tricks.
  const requestPath = new URL(req.url, "http://localhost").pathname;

  if (requestPath !== publicRootPath && !requestPath.startsWith(publicRootPath + "/")) {
    return false;
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.status(405).end();
    return true;
  }

  const projectRoot = path.resolve(__dirname);
  const publicDiskFolder = publicUnknownDir;
  const relativePath =
    requestPath === publicRootPath
      ? path.join("pub", "unknown", "index.html")
      : requestPath.replace(/^\/+/, "");
  const publicDiskPath = path.resolve(projectRoot, relativePath);

  // Check both project root and public folder boundaries.
  if (!isPathInside(publicDiskPath, projectRoot) || !isPathInside(publicDiskPath, publicDiskFolder)) {
    console.log(`[X] PUB: Path traversal blocked for ${requestPath}`);
    console.log("=".repeat(80) + "\n");
    if (!silentNotFound) res.status(404).end();
    return true;
  }

  try {
    if (!fs.existsSync(publicDiskPath)) {
      console.log(`[X] PUB: File not found on disk: ${publicDiskPath}`);
      console.log("=".repeat(80) + "\n");
      if (!silentNotFound) res.status(404).end();
      return true;
    }

    if (!fs.statSync(publicDiskPath).isFile()) {
      console.log(`[X] PUB: Path is not a file: ${publicDiskPath}`);
      console.log("=".repeat(80) + "\n");
      if (!silentNotFound) res.status(404).end();
      return true;
    }

    console.log(`[OK] PUB: Serving public file ${publicDiskPath}`);
    console.log("=".repeat(80) + "\n");
    res.sendFile(publicDiskPath);
    return true;
  } catch (err) {
    console.log(`[X] PUB: Error serving file: ${err.message}`);
    console.log("=".repeat(80) + "\n");
    if (!silentNotFound) res.status(500).end();
    return true;
  }
}

// Static key validation middleware - appears unresponsive without key
app.use((req, res, next) => {
  // Allow unauthenticated public path on main app (HTTPS listener).
  if (servePublicUnknownFile(req, res, { silentNotFound: false })) {
    return;
  }

  // Allow unauthenticated validation path(s) for CA DCV files on the main app.
  // The separate DCV HTTP app below also uses this same helper.
  if (serveDcvValidationFile(req, res, { silentNotFound: true })) {
    return;
  }

  // Check for static key in headers.
  const keyFromHeader = req.get("X-Auth-Key");

  // Set high-trust flag on request object (so endpoints can access it)
  req.isHighTrust = false;

  // Debug: log key comparison details (lengths + first/last char codes) so
  // operators can spot encoding mismatches without leaking full secrets.
  if (envBool("DEBUG_AUTH", false) && keyFromHeader != null) {
    const hdrHex = Buffer.from(keyFromHeader).toString("hex");
    const envHex = Buffer.from(STATIC_KEY).toString("hex");
    console.log(`[DEBUG AUTH] header  len=${keyFromHeader.length} hex=${hdrHex}`);
    console.log(`[DEBUG AUTH] envKey  len=${STATIC_KEY.length} hex=${envHex}`);
    console.log(`[DEBUG AUTH] match=${hdrHex === envHex}`);
  }

  if (safeEqual(keyFromHeader, HT_STATIC_KEY)) {
    req.isHighTrust = true;
    console.log("[OK] AUTH: High-trust key provided");
    console.log("=".repeat(80) + "\n");
    return next();
  }

  if (safeEqual(keyFromHeader, STATIC_KEY)) {
    console.log("[OK] AUTH: Valid key provided");
    console.log("=".repeat(80) + "\n");
    return next();
  }

  // Log unauthorized access attempt but don't respond
  console.log(`[X] BLOCKED: No valid authentication key (header ${keyFromHeader == null ? "missing" : "len=" + keyFromHeader.length})`);
  console.log("=".repeat(80) + "\n");

  // Dedicated blocked log (JSONL)
  logBlockedEvent({
    ts: new Date().toISOString(),
    type: "blocked",
    id: req.requestId || null,
    method: req.method,
    url: req.originalUrl || req.url,
    host: req.hostname,
    ip: req.ip || req.socket?.remoteAddress || req.headers["x-forwarded-for"],
    ua: req.get("User-Agent") || "Unknown",
    reason: "missing_or_invalid_x_auth_key",
  });

  // Tarpit: hold the connection open silently to waste the attacker's
  // resources (threads, sockets, scanner slots).  A random 60-120 s delay
  // is long enough to seriously slow automated scanners while eventually
  // reclaiming our own file descriptor.
  const dropDelay = 60000 + Math.floor(Math.random() * 60000);
  setTimeout(() => {
    try { req.destroy(); } catch { /* already closed */ }
  }, dropDelay);
  return; // Silent drop
});

// Register all application routes (extracted to routes.js)
const registerRoutes = require("./routes");
registerRoutes(app, {
  SERVERURL,
  STATIC_KEY,
  payloadsDir,
  uploadsDir,
  upload,
  multer,
  sanitizePath,
  sanitizeFilename,
});

// Start a separate plain-HTTP listener for DCV validation files only.
// This exposes only DCV_VALIDATION_PATH, not authenticated API routes.
if (envStr("DCV_VALIDATION_PATH", "")) {
  const dcvHttpApp = express();

  dcvHttpApp.disable("x-powered-by");

  dcvHttpApp.use((req, res) => {
    res.setHeader("Server", "PhoneHomeWeb");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");

    if (req.method !== "GET" && req.method !== "HEAD") {
      return res.status(405).end();
    }

    if (serveDcvValidationFile(req, res, { silentNotFound: false })) {
      return;
    }

    return res.status(404).end();
  });

  http.createServer(dcvHttpApp).listen(DCV_HTTP_PORT, DCV_HTTP_BIND_HOST, () => {
    console.log("\n" + "=".repeat(80));
    console.log("DCV HTTP SERVER STARTED - NON-SSL MODE");
    console.log("=".repeat(80));
    console.log(`Port: ${DCV_HTTP_PORT}`);
    console.log(`Listening: ${DCV_HTTP_BIND_HOST}`);
    console.log(`DCV Path: ${envStr("DCV_VALIDATION_PATH", "")}`);
    console.log(`Started: ${new Date().toISOString()}`);
    console.log("=".repeat(80));
    console.log("Waiting for DCV requests...\n");
  });
} else {
  console.log("DCV_VALIDATION_PATH not configured; DCV HTTP server disabled");
}

// Start the main server (HTTPS if certificates available, otherwise HTTP)
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
