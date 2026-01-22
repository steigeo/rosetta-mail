use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::fs;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Global configuration instance
static CONFIG: OnceLock<ClientConfig> = OnceLock::new();

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub mail: MailConfig,
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    #[serde(default)]
    pub accounts: AccountsConfig,
}

/// Server connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// WebSocket URL of the tunnel server
    #[serde(default = "default_server_url")]
    pub url: String,
    /// Authentication key (shared secret with server)
    pub auth_key: Option<String>,
    /// Public IPv4 address of the server (for DNS A records and SPF)
    pub ip: Option<String>,
    /// Public IPv6 address of the server (for DNS AAAA records and SPF)
    pub ipv6: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: default_server_url(),
            auth_key: None,
            ip: None,
            ipv6: None,
        }
    }
}

fn default_server_url() -> String {
    "ws://127.0.0.1:8080".to_string()
}

/// Mail server settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MailConfig {
    /// SMTP hostname (e.g., mail.example.com)
    pub hostname: Option<String>,
    /// Mail domain (e.g., example.com)
    pub domain: Option<String>,
}

/// Cloudflare DNS settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudflareConfig {
    /// API token with DNS edit permissions
    pub api_token: Option<String>,
    /// Zone ID for the mail domain
    pub zone_id: Option<String>,
}

/// Email accounts configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountsConfig {
    /// Map of email address to account info
    #[serde(default)]
    pub users: HashMap<String, AccountInfo>,
}

/// Individual account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Argon2id hashed password
    pub password_hash: String,
}

impl AccountsConfig {
    /// Check if an email address is a valid recipient (has an account)
    pub fn is_valid_recipient(&self, email: &str) -> bool {
        let email_lower = email.to_lowercase();
        self.users.contains_key(&email_lower)
    }

    /// Verify a user's password
    pub fn verify_password(&self, email: &str, password: &str) -> bool {
        let email_lower = email.to_lowercase();
        if let Some(account) = self.users.get(&email_lower) {
            verify_password(password, &account.password_hash)
        } else {
            // Perform a dummy verification to prevent timing attacks
            let _ = verify_password(password, "$argon2id$v=19$m=19456,t=2,p=1$dW5rbm93bg$0000000000000000000000000000000000000000000");
            false
        }
    }
}

/// Hash a password using Argon2id
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

impl ClientConfig {
    /// Load configuration from file, falling back to environment variables
    pub async fn load(storage_path: &PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config_path = storage_path.join("config.toml");
        
        let mut config = if config_path.exists() {
            let content = fs::read_to_string(&config_path).await?;
            toml::from_str(&content)?
        } else {
            ClientConfig::default()
        };

        // Environment variables override config file values
        config.apply_env_overrides();

        Ok(config)
    }

    /// Apply environment variable overrides (for backwards compatibility)
    fn apply_env_overrides(&mut self) {
        // Server settings
        if let Ok(url) = std::env::var("TUNNEL_SERVER_URL") {
            self.server.url = url;
        }
        if let Ok(key) = std::env::var("TUNNEL_AUTH_KEY") {
            self.server.auth_key = Some(key);
        }
        if let Ok(ip) = std::env::var("SERVER_IP") {
            self.server.ip = Some(ip);
        }

        // Mail settings
        if let Ok(hostname) = std::env::var("SMTP_HOSTNAME") {
            self.mail.hostname = Some(hostname);
        }
        if let Ok(domain) = std::env::var("MAIL_DOMAIN") {
            self.mail.domain = Some(domain);
        }

        // Cloudflare settings
        if let Ok(token) = std::env::var("CLOUDFLARE_API_TOKEN") {
            self.cloudflare.api_token = Some(token);
        }
        if let Ok(zone_id) = std::env::var("CLOUDFLARE_ZONE_ID") {
            self.cloudflare.zone_id = Some(zone_id);
        }
    }

    /// Save configuration to file
    pub async fn save(&self, storage_path: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config_path = storage_path.join("config.toml");
        let content = toml::to_string_pretty(self)?;
        fs::write(&config_path, content).await?;
        Ok(())
    }

    /// Generate a sample configuration file
    pub fn sample() -> String {
        let mut users = HashMap::new();
        users.insert(
            "user@example.com".to_string(),
            AccountInfo {
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$EXAMPLE$HASH".to_string(),
            },
        );
        
        let sample = ClientConfig {
            server: ServerConfig {
                url: "ws://your-server:8080".to_string(),
                auth_key: Some("your-secret-key".to_string()),
                ip: Some("203.0.113.1".to_string()),
                ipv6: Some("2001:db8::1".to_string()),
            },
            mail: MailConfig {
                hostname: Some("mail.example.com".to_string()),
                domain: Some("example.com".to_string()),
            },
            cloudflare: CloudflareConfig {
                api_token: Some("your-cloudflare-api-token".to_string()),
                zone_id: Some("your-zone-id".to_string()),
            },
            accounts: AccountsConfig { users },
        };
        toml::to_string_pretty(&sample).unwrap()
    }
}

/// Initialize the global configuration
pub async fn init_config() -> Result<&'static ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let storage_path = get_storage_path();
    let config = ClientConfig::load(&storage_path).await?;
    
    Ok(CONFIG.get_or_init(|| config))
}

/// Get the loaded configuration (panics if not initialized)
pub fn get_config() -> &'static ClientConfig {
    CONFIG.get().expect("Configuration not initialized. Call init_config() first.")
}

/// Get the storage path from environment (this must be available before config is loaded)
pub fn get_storage_path() -> PathBuf {
    std::env::var("TUNNEL_STORAGE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// Convenience functions that read from the global config

/// Get the server URL
pub fn get_server_url() -> String {
    get_config().server.url.clone()
}

/// Get the authentication key
pub fn get_auth_key() -> Option<String> {
    get_config().server.auth_key.clone()
}

/// Get the SMTP hostname
pub fn get_smtp_hostname() -> Option<String> {
    get_config().mail.hostname.clone()
}

/// Get the mail domain
pub fn get_mail_domain() -> Option<String> {
    get_config().mail.domain.clone()
}

/// Get Cloudflare API token
pub fn get_cloudflare_api_token() -> Option<String> {
    get_config().cloudflare.api_token.clone()
}

/// Get Cloudflare Zone ID
pub fn get_cloudflare_zone_id() -> Option<String> {
    get_config().cloudflare.zone_id.clone()
}

/// Get the server IP address (IPv4)
pub fn get_server_ip() -> Option<String> {
    get_config().server.ip.clone()
}

/// Get the server IPv6 address
pub fn get_server_ipv6() -> Option<String> {
    get_config().server.ipv6.clone()
}
