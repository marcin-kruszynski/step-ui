# Step-CA Web UI

A modern web interface for managing certificates with Smallstep Step-CA.

## Features

- Issue certificates with custom SANs
- Sign CSRs
- Certificate inventory management
- Download certificates in various formats (PEM, PFX)
- Audit logging
- Modern, responsive UI

## Prerequisites

- Docker and Docker Compose
- A running Step-CA instance
- Step-CA provisioner credentials

## Configuration

### 1. Get the CA Root Fingerprint

The CA root fingerprint is required for secure communication with Step-CA. You can obtain it in several ways:

**Option A: From the Step-CA server directly**
```bash
# SSH into your Step-CA server and run:
step certificate fingerprint $(step path)/certs/root_ca.crt
```

**Option B: From the Step-CA logs**
When Step-CA starts, it prints the root fingerprint in the logs. Look for a line like:
```
Root fingerprint: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f
```

**Option C: Using curl and openssl**
```bash
# Download the root certificate
curl -sk https://your-ca-url:9000/root > /tmp/root_ca.crt

# Calculate the fingerprint
openssl x509 -in /tmp/root_ca.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':'
```

### 2. Create Environment File

Create a `.env` file in the project root with your Step-CA configuration:

```bash
# Step-CA Configuration
CA_URL=https://ca.home:9000
CA_ROOT_FINGERPRINT=your_root_fingerprint_here
PROVISIONER_NAME=ui-admin
PROVISIONER_PASSWORD=your_provisioner_password
```

**Important:** Replace the values with your actual Step-CA details:
- `CA_URL`: Your Step-CA URL
- `CA_ROOT_FINGERPRINT`: The fingerprint you obtained in step 1
- `PROVISIONER_NAME`: Your provisioner name
- `PROVISIONER_PASSWORD`: Your provisioner password

### 3. Setup Step-CA Provisioner (if not already done)

If you haven't created a provisioner for the UI yet, run this on your Step-CA server:

```bash
step ca provisioner add ui-admin --type=JWK --create
```

Save the password that's generated - you'll need it for the `PROVISIONER_PASSWORD` in your `.env` file.

## Quick Start

1. Clone this repository
2. Configure your `.env` file (see Configuration section above)
3. Start the services:

```bash
./setup.sh
```

Or manually:

```bash
docker compose build
docker compose up -d
```

4. Access the web interface at `http://localhost:3000`

### Optional HTTPS

For production or trusted internal deployments, Step UI can be served over HTTPS using the included Caddy reverse-proxy configuration. The default Docker Compose configuration remains HTTP-only for simple local deployments.

1. Create a DNS record for the hostname that will serve Step UI. Replace `step-ui.example.com` below with the actual DNS hostname for your Step UI installation.

2. Create a `tls` directory and provide the server certificate chain and private key:

       mkdir -p tls
       cp /path/to/fullchain.pem tls/cert.pem
       cp /path/to/privkey.pem tls/privkey.pem
       chmod 600 tls/privkey.pem

   `tls/cert.pem` should contain the server certificate followed by any intermediate certificates required by clients.

3. Set the public hostname and start Step UI with the HTTPS overlay:

       export STEP_UI_HOST=step-ui.example.com
       docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --build

4. Open `https://step-ui.example.com`.

In HTTPS mode, Caddy is the only browser-facing service. It listens on port 443 and proxies `/api/*` and `/health` to the backend while sending all other requests to the frontend. The frontend and backend are not published directly to the host.

HTTPS also provides the secure browser context required for features such as clipboard access and secure certificate-bundle downloads.

## Usage

### Issue a Certificate

1. Navigate to "Issue Certificate" in the navigation menu
2. Enter the Common Name (CN) and any Subject Alternative Names (SANs)
3. Set the validity period
4. Choose the download format (PEM or PFX)
5. Click "Issue Certificate"
6. Download the certificate bundle

### Sign a CSR

1. Navigate to "Sign CSR" in the navigation menu
2. Paste your Certificate Signing Request (CSR) in PEM format
3. Set the validity period
4. Click "Sign CSR"
5. Download the signed certificate

### View Certificate Inventory

1. Navigate to "Inventory" to see all issued certificates
2. View certificate details, status, and expiration dates
3. Filter by status (active, expired, expiring soon)

## Troubleshooting

### Error: 'step ca token' requires the '--root' flag

This error means the `CA_ROOT_FINGERPRINT` is missing or incorrect in your `.env` file. Follow the configuration steps above to obtain and set the correct fingerprint.

### Error: connection refused

- Verify your Step-CA is running and accessible at the configured `CA_URL`
- Check that the CA_URL is correct in your `.env` file
- Ensure there are no firewall rules blocking access

### Error: unauthorized

- Verify your provisioner name and password are correct
- Ensure the provisioner exists on your Step-CA server
- Check the provisioner hasn't been disabled

## Development

### Backend

```bash
cd backend
go run ./cmd
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Architecture

- **Frontend**: Next.js 14 with TypeScript, TailwindCSS
- **Backend**: Go with Gin framework
- **Database**: SQLite for certificate metadata and audit logs
- **CA Integration**: Smallstep Step-CA via CLI

## Security Notes

- Keep your `.env` file secure and never commit it to version control
- The provisioner password is sensitive - protect it appropriately
- Consider using Docker secrets for production deployments
- Use the optional HTTPS reverse proxy for production or trusted internal deployments
- Implement proper authentication and authorization for production use

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
