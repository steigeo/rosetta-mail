# Rosetta Mail

A TCP tunneling application in Rust where a server listens on TCP ports and
forwards traffic via WebSocket to a connected client that handles the protocols.
This allows TLS termination to happen client-side, ensuring only the client can
read their own email.

## Project State

This project is under active development and has not been fully tested yet. More
features are planned like a web UI for setup and better management of multiple
connected clients. This project is not currently production-ready.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Internet                                       │
│                                                                             │
│   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐                 │
│   │ Sending MTA │      │ HTTP Client │      │ IMAP Client │                 │
│   └──────┬──────┘      └──────┬──────┘      └──────┬──────┘                 │
│          │                    │                    │                        │
│          │ SMTP:25            │ HTTP:80/443        │ IMAP:993               │
│          ▼                    ▼                    ▼                        │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │                    Tunnel Server (VPS)                          │       │
│   │   - Accepts TCP connections on ports 25, 80, 443, 993           │       │
│   │   - Forwards raw TCP bytes to client via WebSocket              │       │
│   │   - No TLS termination (encrypted data passes through)          │       │
│   └──────────────────────────────┬──────────────────────────────────┘       │
│                                  │                                          │
│                                  │ WebSocket:8080 (protobuf)                │
│                                  ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │                    Tunnel Client (Home)                         │       │
│   │   - TLS termination (certificates stay client-side)             │       │
│   │   - SMTP server with STARTTLS, DKIM signing                     │       │
│   │   - IMAP server with TLS for reading emails                     │       │
│   │   - HTTPS server for MTA-STS policy                             │       │
│   │   - Outbound email delivery with STARTTLS, DANE, MTA-STS        │       │
│   │   - DNS management via Cloudflare API                           │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **Server**: Listens on TCP ports (25, 80, 443, 993) and WebSocket port (8080).
  Acts as a transparent TCP proxy, forwarding all bytes to the connected client.
- **Client**: Connects to server via WebSocket, receives forwarded TCP traffic,
  and handles protocol-specific logic (SMTP, IMAP, TLS, HTTP). All cryptographic
  keys and certificates remain on the client.

## Building

```bash
cargo build --release
```

## Configuration

### Server

The server uses environment variables:

| Variable          | Required | Default | Description                                                                                        |
| ----------------- | -------- | ------- | -------------------------------------------------------------------------------------------------- |
| `TUNNEL_AUTH_KEY` | No       | None    | Shared secret for authenticating WebSocket connections. If set, clients must provide matching key. |

### Client

The client uses a TOML configuration file stored at
`<storage_path>/config.toml`. Environment variables can override config file
values for backwards compatibility.

#### Config File (`config.toml`)

```toml
[server]
url = "ws://your-server:8080"
auth_key = "your-secret-key"
ip = "203.0.113.1"  # Public IP of tunnel server

[mail]
hostname = "mail.example.com"  # SMTP hostname
domain = "example.com"         # Mail domain

[cloudflare]
api_token = "your-cloudflare-api-token"
zone_id = "your-zone-id"
```

#### Environment Variables (Override)

| Variable               | Config Path            | Description                                      |
| ---------------------- | ---------------------- | ------------------------------------------------ |
| `TUNNEL_STORAGE_PATH`  | -                      | Path for config file, certs, keys, and emails    |
| `TUNNEL_SERVER_URL`    | `server.url`           | WebSocket URL of the tunnel server               |
| `TUNNEL_AUTH_KEY`      | `server.auth_key`      | Shared secret for authenticating with the server |
| `SERVER_IP`            | `server.ip`            | Public IP of server (for DNS A/AAAA records)     |
| `SMTP_HOSTNAME`        | `mail.hostname`        | SMTP hostname (e.g., `mail.example.com`)         |
| `MAIL_DOMAIN`          | `mail.domain`          | Mail domain (e.g., `example.com`)                |
| `CLOUDFLARE_API_TOKEN` | `cloudflare.api_token` | Cloudflare API token with DNS edit permissions   |
| `CLOUDFLARE_ZONE_ID`   | `cloudflare.zone_id`   | Cloudflare Zone ID for the mail domain           |

## Running

### Server

```bash
# Without authentication
./target/release/server

# With authentication
TUNNEL_AUTH_KEY=your-secret-key ./target/release/server
```

The server listens on:

- Port 25 (SMTP)
- Port 80 (HTTP - redirects to HTTPS)
- Port 443 (HTTPS - MTA-STS policy)
- Port 993 (IMAP over TLS)
- Port 8080 (WebSocket for client connections)

### Client

```bash
# Using config file (recommended)
TUNNEL_STORAGE_PATH=/var/lib/private-email ./target/release/client

# Or with environment variables
TUNNEL_STORAGE_PATH=/var/lib/private-email \
SMTP_HOSTNAME=mail.example.com \
MAIL_DOMAIN=example.com \
./target/release/client
```

## Storage Directory Structure

```
<storage_path>/
├── config.toml              # Client configuration
├── certs/
│   ├── hostname.json        # SMTP/IMAP server certificate (Let's Encrypt)
│   └── mta_sts.json         # MTA-STS HTTPS certificate (Let's Encrypt)
├── dkim/
│   ├── private.pem          # DKIM private key (RSA 2048-bit)
│   └── public.pem           # DKIM public key
└── mailboxes/
    └── <email@domain>/
        ├── mailbox.json     # Mailbox state (UIDVALIDITY, UIDNEXT)
        └── messages/
            └── <uid>.json   # Individual email with metadata
```

## Features

### Inbound Email

- **SMTP Server**: RFC 5321 compliant SMTP server for receiving emails
- **STARTTLS**: TLS encryption for inbound SMTP (end-to-end through tunnel)
- **DKIM Signing**: Automatic DKIM signing for outbound emails (RSA 2048-bit)
- **Email Storage**: JSON-based mailbox storage with per-user directories

### Outbound Email

- **SMTP Client**: Sends emails to external servers via tunnel
- **STARTTLS**: End-to-end TLS encryption through the tunnel to remote MTAs
- **MTA-STS Enforcement**: Fetches and enforces MTA-STS policies (RFC 8461)
- **DANE Verification**: TLSA record lookup with DNSSEC validation (RFC 7672)
- **MX Validation**: Validates MX hosts against MTA-STS policy before connecting

### IMAP Access

- **IMAP4rev1 Server**: Read emails via standard IMAP clients
- **IMAP over TLS**: Secure IMAP on port 993
- **Mailbox Support**: INBOX with full UID support

### Security & Certificates

- **ACME/Let's Encrypt**: Automatic certificate issuance via DNS-01 challenge
- **Certificate Storage**: Certificates stored locally with auto-renewal
- **Client-side TLS**: All TLS termination happens on the client, not the server

### DNS Management (Cloudflare)

- **Automatic DNS Records**: MX, A/AAAA, SPF, DKIM, DMARC
- **DANE/TLSA**: Automatic TLSA record publishing with DNSSEC
- **MTA-STS**: Automatic `_mta-sts` TXT record and policy CNAME
- **CAA Records**: Certificate Authority Authorization

## Security Model

The key security property is that **all cryptographic keys remain on the
client**:

1. The tunnel server only sees encrypted TLS traffic
2. TLS handshakes happen between the client and remote parties
3. DKIM private keys never leave the client
4. Email content is only readable by the client

For outbound email, the client verifies remote server security:

1. **MTA-STS**: Checks policy at
   `https://mta-sts.<domain>/.well-known/mta-sts.txt`
2. **DANE**: Looks up TLSA records with DNSSEC validation (ignores unsigned
   records)
3. **TLS Required**: Refuses to send if policy requires TLS but server doesn't
   support it

## License

AGPL-3
