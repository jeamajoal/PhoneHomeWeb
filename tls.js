"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

/**
 * Load and return TLS/SSL options for the HTTPS server.
 *
 * @param {object} opts
 * @param {string} opts.baseDir  - Project root (__dirname from server.js)
 * @param {function} opts.envStr  - Environment string helper
 * @param {function} opts.envBool - Environment boolean helper
 * @returns {object|null} Node.js TLS options object, or null if SSL is disabled / misconfigured
 */
module.exports = function loadTlsOptions({ baseDir, envStr, envBool }) {
  // ---------------------------------------------------------------------------
  // TLS protocol and cipher configuration (TLS 1.2+, strong ciphers, PFS)
  // ---------------------------------------------------------------------------
  const TLS_CONFIG = {
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.3",

    ciphers: [
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_AES_128_GCM_SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES128-GCM-SHA256",
    ].join(":"),

    secureOptions:
      crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,

    honorCipherOrder: true,
    requestCert: false,
    rejectUnauthorized: false,
  };

  // ---------------------------------------------------------------------------
  // Certificate file paths
  // ---------------------------------------------------------------------------
  const certsDir = path.resolve(baseDir, envStr("CERTS_DIR", "certs"));

  const tlsKeyFile = envStr("TLS_KEY_FILE", "");
  const tlsCertFile = envStr("TLS_CERT_FILE", "");
  const tlsCaFile = envStr("TLS_CA_FILE", "");
  const tlsPfxFile = envStr("TLS_PFX_FILE", "");
  const tlsPfxPassphrase = envStr("TLS_PFX_PASSPHRASE", "");

  function resolveIfSet(dir, fileName) {
    if (!fileName) return null;
    return path.resolve(dir, fileName);
  }

  const keyPath = resolveIfSet(certsDir, tlsKeyFile);
  const certPath = resolveIfSet(certsDir, tlsCertFile);
  const caPath = resolveIfSet(certsDir, tlsCaFile);
  const pfxPath = resolveIfSet(certsDir, tlsPfxFile);

  // ---------------------------------------------------------------------------
  // Startup helper: log leaf-cert details so operators can verify the right
  // certificate is loaded (guards against leftover CN=localhost certs).
  // ---------------------------------------------------------------------------
  function logCertDetails(certPem, label) {
    try {
      if (crypto.X509Certificate) {
        const x509 = new crypto.X509Certificate(certPem);
        console.log(`  ${label}:`);
        console.log(`    Subject: ${x509.subject}`);
        console.log(`    Issuer:  ${x509.issuer}`);
        console.log(`    Valid:   ${x509.validFrom} \u2192 ${x509.validTo}`);
        if (x509.subjectAltName) {
          console.log(`    SANs:    ${x509.subjectAltName}`);
        }
      }
    } catch {
      // crypto.X509Certificate not available (Node < 15) or cert parse error
    }
  }

  // ---------------------------------------------------------------------------
  // Early exit if SSL is disabled
  // ---------------------------------------------------------------------------
  if (envBool("DISABLE_SSL", false)) {
    console.log("\n" + "=".repeat(80));
    console.log("SSL DISABLED - Using HTTP mode");
    console.log("=".repeat(80) + "\n");
    return null;
  }

  // Ensure certs directory exists
  if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
  }

  const usingPfx = Boolean(tlsPfxFile);
  const usingPemPair = Boolean(tlsKeyFile && tlsCertFile);

  // ---------------------------------------------------------------------------
  // No cert env vars set at all
  // ---------------------------------------------------------------------------
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
    return null;
  }

  // ---------------------------------------------------------------------------
  // PFX bundle
  // ---------------------------------------------------------------------------
  if (usingPfx && pfxPath && fs.existsSync(pfxPath)) {
    try {
      const opts = {
        ...TLS_CONFIG,
        pfx: fs.readFileSync(pfxPath),
      };

      if (tlsPfxPassphrase) {
        opts.passphrase = tlsPfxPassphrase;
      }

      if (caPath && fs.existsSync(caPath)) {
        opts.ca = fs.readFileSync(caPath);
      }

      console.log("\n" + "=".repeat(80));
      console.log("SSL CERTIFICATES LOADED");
      console.log("=".repeat(80));
      console.log(`PFX bundle: ${pfxPath}`);
      console.log(`CA Bundle: ${caPath && fs.existsSync(caPath) ? caPath : "Not found"}`);
      console.log("=".repeat(80) + "\n");
      return opts;
    } catch (error) {
      console.log("\n" + "=".repeat(80));
      console.log("SSL ERROR - Invalid PFX file");
      console.log("=".repeat(80));
      console.error("Error:", error.message);
      console.log("=".repeat(80) + "\n");
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // PEM key + cert pair
  // ---------------------------------------------------------------------------
  if (usingPemPair && keyPath && certPath && fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    try {
      let certContent = fs.readFileSync(certPath, "utf8");

      let caChainLoaded = false;
      if (caPath && fs.existsSync(caPath)) {
        const caContent = fs.readFileSync(caPath, "utf8");
        certContent = certContent.trimEnd() + "\n" + caContent.trimStart();
        caChainLoaded = true;
      }

      const opts = {
        ...TLS_CONFIG,
        key: fs.readFileSync(keyPath),
        cert: certContent,
      };

      console.log("\n" + "=".repeat(80));
      console.log("SSL CERTIFICATES LOADED");
      console.log("=".repeat(80));
      console.log(`Private key:    ${keyPath}`);
      console.log(`Certificate:    ${certPath}`);
      console.log(`CA chain file:  ${caChainLoaded ? caPath + " (appended to cert chain)" : "Not provided - ensure TLS_CERT_FILE contains the full chain"}`);
      logCertDetails(fs.readFileSync(certPath, "utf8"), "Leaf certificate");
      console.log("=".repeat(80) + "\n");
      return opts;
    } catch (error) {
      console.log("\n" + "=".repeat(80));
      console.log("SSL ERROR - Invalid certificate files");
      console.log("=".repeat(80));
      console.error("Error:", error.message);
      console.log("=".repeat(80) + "\n");
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Env vars set but files missing on disk
  // ---------------------------------------------------------------------------
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
  return null;
};
