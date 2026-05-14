/**
 * User Routes Module
 * 
 * This file is dynamically loaded by routes.js to allow custom route expansion.
 * Add your custom routes here following the pattern below.
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

module.exports = function registerUserRoutes(app, deps) {
  // Example: Custom route for hello world
  // app.get("/custom/hello", (req, res) => {
  //   res.json({ message: "Hello from user routes!" });
  // });

  // Example: Custom file upload endpoint
  // app.post("/custom/upload", deps.upload.single("file"), (req, res) => {
  //   if (!req.file) {
  //     return res.status(400).json({ success: false, error: "No file uploaded" });
  //   }
  //   res.json({ 
  //     success: true, 
  //     filename: req.file.filename,
  //     message: "File uploaded via custom route"
  //   });
  // });

  console.log("[INFO] User routes loaded (add custom routes in data/user-routes/index.js)");
};
