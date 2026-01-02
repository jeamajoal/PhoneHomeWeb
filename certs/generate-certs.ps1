# Generate TLS certificates using OpenSSL
Write-Host "Generating TLS certificates for secure HTTPS server..." -ForegroundColor Cyan

$CommonName = if ($env:PHW_TLS_CN) { $env:PHW_TLS_CN } else { "your.domain.example" }

# Create certs directory
if (-not (Test-Path "certs")) {
    New-Item -ItemType Directory -Name "certs" | Out-Null
}

Set-Location "certs"

Write-Host "Step 1: Generating CA certificate..." -ForegroundColor Yellow
# Generate CA private key
openssl genrsa -out ca-key.pem 2048

# Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=PhoneHomeWeb-CA"

Write-Host "Step 2: Generating server certificate..." -ForegroundColor Yellow
# Generate server private key
openssl genrsa -out server-key.pem 2048

# Generate server certificate signing request
openssl req -new -key server-key.pem -out server-csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=$CommonName"

# Generate server certificate signed by CA
openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365

Write-Host "Step 3: Generating client certificate (optional)..." -ForegroundColor Yellow
# Generate client private key
openssl genrsa -out client-key.pem 2048

# Generate client certificate signing request
openssl req -new -key client-key.pem -out client-csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=PhoneHomeWeb-Client"

# Generate client certificate signed by CA
openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365

Write-Host "Certificate generation complete!" -ForegroundColor Green
Write-Host "Generated files:" -ForegroundColor Gray
Write-Host "  ca-cert.pem - Certificate Authority certificate" -ForegroundColor Gray
Write-Host "  ca-key.pem - Certificate Authority private key" -ForegroundColor Gray
Write-Host "  server-cert.pem - Server certificate" -ForegroundColor Gray
Write-Host "  server-key.pem - Server private key" -ForegroundColor Gray
Write-Host "  client-cert.pem - Client certificate (for mutual authentication)" -ForegroundColor Gray
Write-Host "  client-key.pem - Client private key" -ForegroundColor Gray

Set-Location ..
