/// Server configuration constants
/// TCP ports to listen on:
/// - 25: SMTP (receiving mail)
/// - 80: HTTP (for redirects to HTTPS)
/// - 443: HTTPS (for MTA-STS policy serving)
/// - 143: IMAP (explicit TLS via STARTTLS)
/// - 465: SMTP Submission (implicit TLS)
/// - 587: SMTP Submission (explicit TLS via STARTTLS)
/// - 993: IMAPS (implicit TLS)
pub const TCP_PORTS: &[u16] = &[25, 80, 143, 443, 465, 587, 993];
pub const WEBSOCKET_PORT: u16 = 8080;

/// Environment variable name for the authentication key
pub const AUTH_KEY_ENV: &str = "TUNNEL_AUTH_KEY";

/// Get the authentication key from environment
pub fn get_auth_key() -> Option<String> {
    std::env::var(AUTH_KEY_ENV).ok()
}
