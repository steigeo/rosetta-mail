use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;
use rustls::ServerConnection;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use super::certificate::StoredCertificate;

/// Certificate resolver that uses SNI to select certificates
pub struct SniCertResolver {
    /// Map of hostname to certificate
    certificates: HashMap<String, Arc<CertifiedKey>>,
    /// Default certificate if no SNI match
    default_cert: Option<Arc<CertifiedKey>>,
}

impl Default for SniCertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SniCertResolver {
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            default_cert: None,
        }
    }

    /// Add a certificate for a specific hostname
    pub fn add_certificate(
        &mut self,
        hostname: &str,
        cert: &StoredCertificate,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cert_chain = cert.cert_chain()?;
        let private_key = cert.private_key()?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)?;
        let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

        // Add for the exact hostname
        self.certificates
            .insert(hostname.to_lowercase(), certified_key.clone());

        // Set as default if first certificate
        if self.default_cert.is_none() {
            self.default_cert = Some(certified_key);
        }

        Ok(())
    }

    /// Set the default certificate
    pub fn set_default(&mut self, cert: &StoredCertificate) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cert_chain = cert.cert_chain()?;
        let private_key = cert.private_key()?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)?;
        let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

        self.default_cert = Some(certified_key);
        Ok(())
    }
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("hostnames", &self.certificates.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Try to get SNI from client hello
        if let Some(server_name) = client_hello.server_name() {
            let name_lower = server_name.to_lowercase();
            println!("TLS SNI requested: {}", name_lower);

            // Try exact match
            if let Some(cert) = self.certificates.get(&name_lower) {
                println!("  Using certificate for: {}", name_lower);
                return Some(cert.clone());
            }

            // Try wildcard match (e.g., *.example.com)
            if let Some(dot_pos) = name_lower.find('.') {
                let wildcard = format!("*{}", &name_lower[dot_pos..]);
                if let Some(cert) = self.certificates.get(&wildcard) {
                    println!("  Using wildcard certificate for: {}", wildcard);
                    return Some(cert.clone());
                }
            }

            println!("  No specific certificate found, using default");
        } else {
            println!("TLS: No SNI provided, using default certificate");
        }

        // Fall back to default
        self.default_cert.clone()
    }
}

/// TLS session wrapper for SMTP STARTTLS
pub struct TlsSession {
    connection: ServerConnection,
}

impl TlsSession {
    /// Create a new TLS session from a stored certificate
    pub fn new(cert: &StoredCertificate) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert_chain = cert.cert_chain()?;
        let private_key = cert.private_key()?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        let connection = ServerConnection::new(Arc::new(config))?;

        Ok(Self { connection })
    }

    /// Create a new TLS session with SNI-based certificate selection
    pub fn new_with_sni_resolver(resolver: Arc<SniCertResolver>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);

        let connection = ServerConnection::new(Arc::new(config))?;

        Ok(Self { connection })
    }

    /// Process incoming ciphertext data from the network
    /// Returns any decrypted plaintext data
    pub fn process_incoming(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Feed ciphertext to rustls
        let mut reader = std::io::Cursor::new(ciphertext);
        match self.connection.read_tls(&mut reader) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }

        // Process any TLS state changes
        match self.connection.process_new_packets() {
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        }

        // Read any available plaintext
        let mut plaintext = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match self.connection.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(plaintext)
    }

    /// Encrypt plaintext data for sending over the network
    /// Returns ciphertext to be sent
    pub fn process_outgoing(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Write plaintext to rustls
        if !plaintext.is_empty() {
            self.connection.writer().write_all(plaintext)?;
        }

        // Get ciphertext output
        let mut ciphertext = Vec::new();
        loop {
            match self.connection.write_tls(&mut ciphertext) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(ciphertext)
    }

    /// Get any pending ciphertext that needs to be sent (e.g., handshake data)
    pub fn get_pending_ciphertext(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut ciphertext = Vec::new();
        loop {
            match self.connection.write_tls(&mut ciphertext) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(ciphertext)
    }

    /// Check if the TLS handshake is complete
    pub fn is_handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }

    /// Check if the connection wants to write data
    pub fn wants_write(&self) -> bool {
        self.connection.wants_write()
    }

    /// Check if the connection wants to read data
    pub fn wants_read(&self) -> bool {
        self.connection.wants_read()
    }
}
