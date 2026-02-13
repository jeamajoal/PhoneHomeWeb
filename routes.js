"use strict";

const path = require("path");
const fs = require("fs");

/**
 * Register all application routes.
 *
 * @param {import('express').Express} app - Express application
 * @param {object} deps - Shared dependencies from server.js
 * @param {string} deps.SERVERURL - Configured server URL for placeholder injection
 * @param {string} deps.payloadsDir - Absolute path to payloads directory
 * @param {string} deps.uploadsDir - Absolute path to uploads directory
 * @param {import('multer').Multer} deps.upload - Configured multer instance
 * @param {typeof import('multer')} deps.multer - Multer module (for MulterError)
 * @param {function} deps.sanitizePath - Path traversal prevention helper
 * @param {function} deps.sanitizeFilename - Filename sanitization helper
 */
module.exports = function registerRoutes(app, deps) {
  const {
    SERVERURL,
    payloadsDir,
    uploadsDir,
    upload,
    multer,
    sanitizePath,
    sanitizeFilename,
  } = deps;

  // ---------------------------------------------------------------------------
  // Root endpoint - appears unresponsive (tarpit for scanners)
  // ---------------------------------------------------------------------------
  app.get("/", (req, res) => {
    console.log(`[!] PROBE: Root endpoint accessed (no response sent)`);
    console.log("=".repeat(80) + "\n");
    const dropDelay = 60000 + Math.floor(Math.random() * 60000);
    setTimeout(() => {
      try { req.destroy(); } catch { /* already closed */ }
    }, dropDelay);
  });

  // ---------------------------------------------------------------------------
  // Helper: replace <<PARAM>> placeholders in file content or on-disk file
  // ---------------------------------------------------------------------------
  function getFileWithParamOverwrite(paramName, value, filePathOrContent) {
    let content;

    if (typeof filePathOrContent === "string" && fs.existsSync(filePathOrContent)) {
      content = fs.readFileSync(filePathOrContent, "utf8");
    } else if (typeof filePathOrContent === "string") {
      content = filePathOrContent;
    } else {
      throw new Error("Invalid input: must be file path or content string");
    }

    const replacementValue = value !== undefined && value !== null ? value : "";
    const escaped = paramName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return content.replace(new RegExp(`<<${escaped}>>`, "g"), replacementValue);
  }

  // ---------------------------------------------------------------------------
  // Helper: serve a text file with <<SERVERURL>> and <<AUTHKEY>> injected
  // ---------------------------------------------------------------------------
  function serveInstallerWithAuthKey(req, res, filePathOrContent, filename = null) {
    try {
      let fileContent;
      let outputFilename;

      if (fs.existsSync(filePathOrContent)) {
        fileContent = fs.readFileSync(filePathOrContent, "utf8");
        outputFilename = filename || path.basename(filePathOrContent);
      } else {
        fileContent = filePathOrContent;
        outputFilename = filename || "installer.ps1";
      }

      const authKey = req.get("X-Auth-Key") || "";
      const serverUrl = typeof SERVERURL === "string" ? SERVERURL : "";
      const updatedContent = fileContent
        .replace(/<<SERVERURL>>/g, serverUrl)
        .replace(/<<AUTHKEY>>/g, authKey);

      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("Content-Disposition", `inline; filename="${outputFilename}"`);
      res.setHeader("X-Placeholders-Injected", "SERVERURL,AUTHKEY");
      res.send(updatedContent);
    } catch (error) {
      console.error("Error serving installer:", error);
      res.status(500).json({ success: false, error: "Error serving installer" });
    }
  }

  // ---------------------------------------------------------------------------
  // Data-driven installer routes (eliminates copy-paste)
  // ---------------------------------------------------------------------------
  const installerRoutes = [
    {
      route: "/winpe-usb-installer",
      folder: "WinPECollector",
      file: "install-winpe-usb-builder.ps1",
    },
    {
      route: "/winpecollector-installer",
      folder: "WinPECollector",
      file: "install-winpecollector.ps1",
    },
    {
      route: "/linux-usb-installer",
      folder: "LinuxCollector",
      file: "install-linux-usb-builder.sh",
    },
    {
      route: "/linuxcollector-installer",
      folder: "LinuxCollector",
      file: "install-linuxcollector.sh",
    },
    {
      route: "/windowscollector-installer",
      folder: "WindowsCollector",
      file: "install-windowscollector.ps1",
    },
    {
      route: "/linux-upload-script",
      folder: "LinuxCollector",
      file: "upload-file.sh",
    },
    {
      route: "/linux-collect-logs",
      folder: "LinuxCollector",
      file: "collect-windows-logs.sh",
    },
  ];

  for (const { route, folder, file } of installerRoutes) {
    app.get(route, (req, res) => {
      try {
        const scriptPath = path.join(payloadsDir, folder, file);
        if (!fs.existsSync(scriptPath)) {
          return res.status(404).json({ success: false, error: `${file} not found` });
        }
        const content = getFileWithParamOverwrite("SERVERURL", SERVERURL, scriptPath);
        serveInstallerWithAuthKey(req, res, content, file);
      } catch (error) {
        console.error(`Error in ${route}:`, error.message);
        res.status(500).json({ success: false, error: "Error loading installer" });
      }
    });
  }

  // ---------------------------------------------------------------------------
  // FileUpload endpoint (requires X-File-Path header)
  // ---------------------------------------------------------------------------
  app.get("/fileupload", (req, res) => {
    try {
      const installerPath = path.join(payloadsDir, "FileUpload", "FileUpload.ps1");
      if (!fs.existsSync(installerPath)) {
        return res.status(404).json({ success: false, error: "FileUpload.ps1 not found" });
      }

      const filePath = req.get("X-File-Path");
      if (!filePath) {
        return res.status(400).json({ success: false, error: "X-File-Path header required" });
      }

      let content = getFileWithParamOverwrite("SERVERURL", SERVERURL, installerPath);
      content = getFileWithParamOverwrite("FILEPATH", filePath, content);
      serveInstallerWithAuthKey(req, res, content, "FileUpload.ps1");
    } catch (error) {
      console.error("Error in /fileupload endpoint:", error.message);
      res.status(500).json({ success: false, error: "Error preparing file upload script" });
    }
  });

  // ---------------------------------------------------------------------------
  // WinPE Drivers -- hierarchical list of driver packages
  // ---------------------------------------------------------------------------
  app.get("/winpe-drivers", (req, res) => {
    try {
      const driversDir = path.join(payloadsDir, "WinPeDrivers");
      if (!fs.existsSync(driversDir)) {
        return res.status(404).json({ success: false, error: "WinPeDrivers directory not found" });
      }

      const manufacturerFilter = req.query.manufacturer
        ? req.query.manufacturer.toLowerCase()
        : null;
      const typeFilter = req.query.type ? req.query.type.toLowerCase() : null;

      const drivers = [];
      const MAX_DEPTH = 10;

      function findDriverPackages(basePath, relativePath = "", depth = 0) {
        if (depth > MAX_DEPTH) return;
        const items = fs.readdirSync(basePath);
        const hasInfFiles = items.some((i) => i.toLowerCase().endsWith(".inf"));

        if (hasInfFiles) {
          const infFiles = items.filter((i) => i.toLowerCase().endsWith(".inf"));
          const allFiles = items.filter((i) =>
            fs.statSync(path.join(basePath, i)).isFile()
          );
          const pathParts = relativePath.split("/");
          const manufacturer = pathParts[0] || "";
          const topLevelFolder = pathParts[1] || "";

          if (manufacturerFilter && manufacturer.toLowerCase() !== manufacturerFilter) return;
          if (typeFilter && !topLevelFolder.toLowerCase().includes(typeFilter)) return;

          drivers.push({
            path: relativePath,
            name: path.basename(relativePath),
            manufacturer,
            topLevelFolder,
            infFiles,
            totalFiles: allFiles.length,
            hasSubdirs: items.some((i) =>
              fs.statSync(path.join(basePath, i)).isDirectory()
            ),
          });
        }

        const subdirs = items.filter((i) =>
          fs.statSync(path.join(basePath, i)).isDirectory()
        );
        for (const subdir of subdirs) {
          const newRel = relativePath ? `${relativePath}/${subdir}` : subdir;
          findDriverPackages(path.join(basePath, subdir), newRel, depth + 1);
        }
      }

      let startPath = driversDir;
      let startRelativePath = "";

      if (manufacturerFilter) {
        const manufacturers = fs
          .readdirSync(driversDir)
          .filter((i) => fs.statSync(path.join(driversDir, i)).isDirectory());
        const matched = manufacturers.find((m) => m.toLowerCase() === manufacturerFilter);
        if (matched) {
          startPath = path.join(driversDir, matched);
          startRelativePath = matched;
        } else {
          return res.json({
            success: true,
            count: 0,
            drivers: [],
            filters: { manufacturer: manufacturerFilter, type: typeFilter },
          });
        }
      }

      findDriverPackages(startPath, startRelativePath);

      res.json({
        success: true,
        count: drivers.length,
        drivers: drivers.sort((a, b) => a.path.localeCompare(b.path)),
        filters: { manufacturer: manufacturerFilter, type: typeFilter },
      });
    } catch (error) {
      console.error("Error in /winpe-drivers endpoint:", error.message);
      res.status(500).json({ success: false, error: "Error retrieving WinPE drivers" });
    }
  });

  // ---------------------------------------------------------------------------
  // File upload (POST)
  // ---------------------------------------------------------------------------
  app.post("/upload", upload.single("file"), (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ success: false, error: "No file uploaded" });
      }

      const fileInfo = {
        success: true,
        savedAs: req.file.filename,
        size: req.file.size,
        uploadedAt: new Date().toISOString(),
      };

      console.log("=".repeat(80));
      console.log(`  [OK] UPLOAD SUCCESS:`);
      console.log(`    Original: ${req.file.originalname}`);
      console.log(`    Saved As: ${req.file.filename}`);
      console.log(`    Size: ${(req.file.size / 1024 / 1024).toFixed(2)} MB`);
      console.log("=".repeat(80) + "\n");

      res.json(fileInfo);
    } catch (error) {
      console.error("Upload error:", error);
      res.status(500).json({ success: false, error: "Internal server error during upload" });
    }
  });

  // ---------------------------------------------------------------------------
  // List uploaded files (high-trust only)
  // ---------------------------------------------------------------------------
  app.get("/uploads", (req, res) => {
    if (req.isHighTrust !== true) {
      console.log(`[X] BLOCKED: Download requires high-trust authentication key`);
      console.log("=".repeat(80) + "\n");
      return res.status(403).json({
        success: false,
        error: "High-trust authentication key required",
      });
    }
    try {
      const files = fs.readdirSync(uploadsDir).map((filename) => {
        const filePath = path.join(uploadsDir, filename);
        const stats = fs.statSync(filePath);
        return {
          filename,
          size: stats.size,
          uploadedAt: stats.birthtime.toISOString().split("T")[0],
        };
      });

      res.json({ success: true, count: files.length, files });
    } catch (error) {
      console.error("Error listing files:", error);
      res.status(500).json({ success: false, error: "Unable to list files" });
    }
  });

  // ---------------------------------------------------------------------------
  // List available payloads
  // ---------------------------------------------------------------------------
  app.get("/payloads", (req, res) => {
    try {
      if (!fs.existsSync(payloadsDir)) {
        return res.status(404).json({ success: false, error: "Payloads directory not found" });
      }

      const folders = fs
        .readdirSync(payloadsDir)
        .filter((f) => fs.statSync(path.join(payloadsDir, f)).isDirectory());

      const payloads = folders.map((folder) => {
        const configPath = path.join(payloadsDir, folder, "config.json");
        if (!fs.existsSync(configPath)) {
          return { folder, name: folder, version: "unknown", description: "", endpoint: "" };
        }
        try {
          const configContent = fs.readFileSync(configPath, "utf-8");
          if (configContent.length > 1024 * 1024) throw new Error("Config file too large");

          const config = JSON.parse(configContent);
          if (typeof config !== "object" || config === null || Array.isArray(config)) {
            throw new Error("Invalid config structure");
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
          return { folder, name: folder, version: "unknown", description: "", endpoint: "" };
        }
      });

      res.json({ success: true, count: payloads.length, payloads });
    } catch (error) {
      console.error("Error listing payloads:", error);
      res.status(500).json({ success: false, error: "Unable to list payloads" });
    }
  });

  // ---------------------------------------------------------------------------
  // Download payload files
  // ---------------------------------------------------------------------------
  app.get("/payloads/:folder/download/:filename", (req, res) => {
    try {
      const folder = sanitizePath(req.params.folder);
      const filename = sanitizePath(req.params.filename);
      const filePath = path.join(payloadsDir, folder, filename);

      const resolvedPath = path.resolve(filePath);
      const resolvedPayloadsDir = path.resolve(payloadsDir);
      if (!resolvedPath.startsWith(resolvedPayloadsDir)) {
        console.log(
          `[X] BLOCKED: Path traversal attempt detected: ${req.params.folder}/${req.params.filename}`
        );
        return res.status(403).json({ success: false, error: "Access denied" });
      }

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ success: false, error: "Payload file not found" });
      }

      const ext = path.extname(filename).toLowerCase();
      const textExts = new Set([
        ".ps1", ".psm1", ".psd1", ".json", ".txt",
        ".md", ".cmd", ".bat", ".sh",
      ]);

      // Binary files: send as-is (UTF-8 rewriting would corrupt them)
      if (!textExts.has(ext)) {
        const safeName = sanitizeFilename(path.basename(filename));
        res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
        return res.sendFile(resolvedPath);
      }

      let content = getFileWithParamOverwrite("SERVERURL", SERVERURL, filePath);
      content = getFileWithParamOverwrite("FILEPATH", filePath, content);
      serveInstallerWithAuthKey(req, res, content, path.basename(filename));
    } catch (error) {
      console.error("Path sanitization error:", error.message);
      res.status(400).json({ success: false, error: "Invalid path parameters" });
    }
  });

  // ---------------------------------------------------------------------------
  // Download specific uploaded file (high-trust only)
  // ---------------------------------------------------------------------------
  app.get("/download", (req, res) => {
    if (req.isHighTrust !== true) {
      console.log(`[X] BLOCKED: Download requires high-trust authentication key`);
      console.log("=".repeat(80) + "\n");
      return res.status(403).json({
        success: false,
        error: "High-trust authentication key required",
      });
    }

    if (!req.get("X-Filename")) {
      return res.status(400).json({ success: false, error: "X-Filename header required" });
    }

    const filenameHeader = req.get("X-Filename");

    try {
      console.log(`  [OK] DOWNLOAD REQUEST for file: ${filenameHeader}`);
      const filename = sanitizePath(filenameHeader);
      console.log(`  [OK] SANITIZED FILENAME: ${filename}`);
      const filePath = path.join(uploadsDir, filename);

      const resolvedPath = path.resolve(filePath);
      const resolvedUploadsDir = path.resolve(uploadsDir);
      if (!resolvedPath.startsWith(resolvedUploadsDir)) {
        console.log(`[X] BLOCKED: Path traversal attempt detected: ${filenameHeader}`);
        return res.status(403).json({ success: false, error: "Access denied" });
      }

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ success: false, error: "File not found" });
      }

      const safeFilename = sanitizeFilename(path.basename(filename));
      let downloadAborted = false;

      req.on("close", () => {
        if (!res.writableEnded) {
          downloadAborted = true;
          console.log(`[!] DOWNLOAD ABORTED by client: ${safeFilename}`);
        }
      });

      req.on("error", (err) => {
        downloadAborted = true;
        console.error(`[!] DOWNLOAD ERROR (client): ${safeFilename}:`, err.message);
      });

      const fileStream = fs.createReadStream(filePath);

      fileStream.on("error", (err) => {
        console.error(`[!] FILE STREAM ERROR: ${safeFilename}:`, err.message);
        if (!res.headersSent) {
          res.status(500).json({ success: false, error: "Error reading file" });
        }
      });

      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Disposition", `attachment; filename="${safeFilename}"`);
      res.setHeader("Content-Length", fs.statSync(filePath).size);

      fileStream.pipe(res);

      fileStream.on("end", () => {
        if (!downloadAborted) {
          console.log(`[OK] DOWNLOAD COMPLETED: ${safeFilename}`);
        }
      });
    } catch (error) {
      console.error("Path sanitization error:", error.message);
      res.status(400).json({ success: false, error: "Invalid filename parameter" });
    }
  });

  // ---------------------------------------------------------------------------
  // Error handling middleware -- must be registered last
  // ---------------------------------------------------------------------------
  app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
      if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ success: false, error: "File size limit exceeded" });
      }
      return res.status(400).json({ success: false, error: "Upload error" });
    }

    console.error("Server error:", error);
    res.status(500).json({ success: false, error: "Internal server error" });
  });
};
