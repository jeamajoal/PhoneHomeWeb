"use strict";

const path = require("path");
const fs = require("fs");

/**
 * Initialise structured request and blocked-request loggers.
 *
 * @param {object} opts
 * @param {string} opts.baseDir        - Project root (__dirname from server.js)
 * @param {function} opts.envStr       - Environment string helper
 * @returns {{ logRequestEvent, logBlockedEvent, shutdown }}
 */
module.exports = function createLogger({ baseDir, envStr }) {
  // ---------------------------------------------------------------------------
  // Path resolution
  // ---------------------------------------------------------------------------
  const requestLogDir = path.resolve(baseDir, envStr("REQUEST_LOG_DIR", "logs"));
  const requestLogPathRaw = envStr("REQUEST_LOG_PATH", "request_logs.jsonl");
  const blockedLogPathRaw = envStr("BLOCKED_LOG_PATH", "blocked.jsonl");

  const requestLogPath = path.isAbsolute(requestLogPathRaw)
    ? requestLogPathRaw
    : requestLogPathRaw.includes("/") || requestLogPathRaw.includes("\\")
      ? path.resolve(baseDir, requestLogPathRaw)
      : path.join(requestLogDir, requestLogPathRaw);

  const blockedLogPath = path.isAbsolute(blockedLogPathRaw)
    ? blockedLogPathRaw
    : blockedLogPathRaw.includes("/") || blockedLogPathRaw.includes("\\")
      ? path.resolve(baseDir, blockedLogPathRaw)
      : path.join(requestLogDir, blockedLogPathRaw);

  // ---------------------------------------------------------------------------
  // Request log stream (append-only, single file)
  // ---------------------------------------------------------------------------
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

  // ---------------------------------------------------------------------------
  // Blocked log stream (daily rotation)
  // ---------------------------------------------------------------------------
  let blockedLogStream = null;
  let blockedLogDate = null;

  function ymd(dateObj) {
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

  // ---------------------------------------------------------------------------
  // Serialisation helpers
  // ---------------------------------------------------------------------------
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

  // ---------------------------------------------------------------------------
  // Graceful shutdown helper (called from SIGINT / SIGTERM handlers)
  // ---------------------------------------------------------------------------
  function shutdown() {
    if (requestLogStream) requestLogStream.end();
    if (blockedLogStream) blockedLogStream.end();
  }

  return { logRequestEvent, logBlockedEvent, shutdown };
};
