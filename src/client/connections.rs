use crate::client::config::AccountsConfig;
use crate::client::http::HttpSession;
use crate::client::imap::ImapSession;
use crate::client::smtp::{MailTransaction, SmtpSession};
use crate::client::storage::EmailStorage;
use crate::client::tls::certificate::StoredCertificate;
use crate::client::tls::session::{SniCertResolver, TlsSession};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};

/// Information about a connection
pub struct ConnectionInfo {
    pub connection_id: u64,
    pub port: u32,
    pub remote_address: String,
    pub protocol_state: ProtocolState,
}

/// Protocol-specific state for a connection
pub enum ProtocolState {
    /// SMTP session (port 25) - plaintext
    Smtp(SmtpSession),
    /// SMTP session with TLS (after STARTTLS)
    SmtpTls {
        tls_session: TlsSession,
        smtp_session: SmtpSession,
    },
    /// SMTP submission session (ports 465/587) - for authenticated sending
    SmtpSubmission(SmtpSession),
    /// SMTP submission with TLS
    SmtpSubmissionTls {
        tls_session: TlsSession,
        smtp_session: SmtpSession,
    },
    /// IMAP session (port 143) - plaintext
    Imap(ImapSession),
    /// IMAP session with TLS (port 993 or after STARTTLS)
    ImapTls {
        tls_session: TlsSession,
        imap_session: ImapSession,
    },
    /// HTTP session (port 80)
    Http(HttpSession),
    /// HTTPS session (port 443) - with TLS unwrapping
    Https {
        tls_session: TlsSession,
        http_session: HttpSession,
    },
    /// Outbound connection (client-initiated)
    Outbound,
    /// Unknown/generic protocol
    Unknown,
}

/// Pending outbound connection request
pub struct PendingOutbound {
    pub result_tx: oneshot::Sender<Result<(), String>>,
}

/// Manages active connections and their state
pub struct ConnectionManager {
    connections: HashMap<u64, ConnectionInfo>,
    /// Pending outbound connection requests awaiting response
    pending_outbound: HashMap<u64, PendingOutbound>,
    /// Callback for completed emails
    pub on_email_received: Option<Box<dyn Fn(MailTransaction) + Send + Sync>>,
    /// Whether TLS is available for STARTTLS
    tls_available: bool,
    /// Hostname for the mail server (e.g., mail.example.com)
    hostname: String,
    /// Mail domain for HTTP responses (e.g., example.com)
    mail_domain: String,
    /// Certificate for TLS termination (SMTP STARTTLS)
    certificate: Option<StoredCertificate>,
    /// Certificate for MTA-STS HTTPS (no longer used - now uses SNI resolver)
    #[allow(dead_code)]
    mta_sts_certificate: Option<StoredCertificate>,
    /// SNI certificate resolver for HTTPS connections
    sni_resolver: Option<Arc<SniCertResolver>>,
    /// Accounts configuration for authentication
    accounts: AccountsConfig,
    /// Email storage
    storage: Arc<EmailStorage>,
}

impl ConnectionManager {
    pub fn new(storage_path: &std::path::Path) -> Self {
        Self {
            connections: HashMap::new(),
            pending_outbound: HashMap::new(),
            on_email_received: None,
            tls_available: false,
            hostname: String::new(),
            mail_domain: String::new(),
            certificate: None,
            mta_sts_certificate: None,
            sni_resolver: None,
            accounts: AccountsConfig::default(),
            storage: Arc::new(EmailStorage::new(storage_path)),
        }
    }

    pub fn new_with_tls(
        hostname: String,
        mail_domain: String,
        tls_available: bool,
        certificate: Option<StoredCertificate>,
        mta_sts_certificate: Option<StoredCertificate>,
        accounts: AccountsConfig,
        storage: Arc<EmailStorage>,
    ) -> Self {
        
        // Build SNI resolver with both certificates
        let mut resolver = SniCertResolver::new();
        
        // Add hostname certificate (for SMTP STARTTLS, IMAP, submission)
        if let Some(ref cert) = certificate {
            if let Err(e) = resolver.add_certificate(&hostname, cert) {
                eprintln!("Warning: Failed to add hostname certificate to SNI resolver: {}", e);
            }
        }
        
        // Add mta-sts certificate (for HTTPS)
        if let Some(ref cert) = mta_sts_certificate {
            let mta_sts_host = format!("mta-sts.{}", mail_domain);
            if let Err(e) = resolver.add_certificate(&mta_sts_host, cert) {
                eprintln!("Warning: Failed to add mta-sts certificate to SNI resolver: {}", e);
            }
        }
        
        let sni_resolver = if certificate.is_some() || mta_sts_certificate.is_some() {
            Some(Arc::new(resolver))
        } else {
            None
        };
        
        Self {
            connections: HashMap::new(),
            pending_outbound: HashMap::new(),
            on_email_received: None,
            tls_available,
            hostname,
            mail_domain,
            certificate,
            mta_sts_certificate,
            sni_resolver,
            accounts,
            storage,
        }
    }

    /// Register a new connection
    pub fn add_connection(
        &mut self,
        connection_id: u64,
        port: u32,
        remote_address: String,
    ) -> (Option<Vec<u8>>, bool) {
        let hostname = self.hostname.clone();
        let mail_domain = if self.mail_domain.is_empty() {
            hostname.clone()
        } else {
            self.mail_domain.clone()
        };
        
        let (protocol_state, initial_response) = match port {
            25 => {
                // SMTP for receiving mail (port 25)
                let mut session = SmtpSession::new(&hostname, &remote_address);
                session.set_tls_available(self.tls_available);
                let greeting = session.greeting();
                (ProtocolState::Smtp(session), Some(greeting))
            }
            80 => {
                let session = HttpSession::new(&hostname, &mail_domain, false);
                (ProtocolState::Http(session), None)
            }
            143 => {
                // IMAP with STARTTLS (port 143)
                let mut session = ImapSession::new(&hostname, self.accounts.clone(), self.storage.clone(), false);
                let greeting = session.greeting();
                (ProtocolState::Imap(session), Some(greeting))
            }
            443 => {
                // For HTTPS, we need TLS termination with SNI support
                if let Some(ref resolver) = self.sni_resolver {
                    // Use SNI resolver for certificate selection
                    match TlsSession::new_with_sni_resolver(resolver.clone()) {
                        Ok(mut tls_session) => {
                            // Get any initial TLS handshake data (server hello, etc.)
                            let handshake_data = tls_session.get_pending_ciphertext().ok();
                            let http_session = HttpSession::new(&hostname, &mail_domain, true);
                            (
                                ProtocolState::Https { tls_session, http_session },
                                handshake_data.filter(|d| !d.is_empty()),
                            )
                        }
                        Err(e) => {
                            eprintln!("Failed to create TLS session for HTTPS: {}", e);
                            return (None, true);
                        }
                    }
                } else if let Some(ref cert) = self.certificate {
                    // Fallback to single certificate
                    match TlsSession::new(cert) {
                        Ok(mut tls_session) => {
                            let handshake_data = tls_session.get_pending_ciphertext().ok();
                            let http_session = HttpSession::new(&hostname, &mail_domain, true);
                            (
                                ProtocolState::Https { tls_session, http_session },
                                handshake_data.filter(|d| !d.is_empty()),
                            )
                        }
                        Err(e) => {
                            eprintln!("Failed to create TLS session for HTTPS: {}", e);
                            return (None, true);
                        }
                    }
                } else {
                    eprintln!("HTTPS connection but no certificate available");
                    return (None, true);
                }
            }
            465 => {
                // SMTP Submission with implicit TLS (port 465)
                if let Some(ref resolver) = self.sni_resolver {
                    match TlsSession::new_with_sni_resolver(resolver.clone()) {
                        Ok(mut tls_session) => {
                            let handshake_data = tls_session.get_pending_ciphertext().ok();
                            let mut smtp_session = SmtpSession::new(&hostname, &remote_address);
                            smtp_session.set_submission_mode(true);
                            smtp_session.set_tls_enabled(true); // Implicit TLS
                            smtp_session.set_accounts(self.accounts.clone());
                            (
                                ProtocolState::SmtpSubmissionTls { tls_session, smtp_session },
                                handshake_data.filter(|d| !d.is_empty()),
                            )
                        }
                        Err(e) => {
                            eprintln!("Failed to create TLS session for SMTP submission: {}", e);
                            return (None, true);
                        }
                    }
                } else {
                    eprintln!("SMTP submission (465) but no certificate available");
                    return (None, true);
                }
            }
            587 => {
                // SMTP Submission with STARTTLS (port 587)
                let mut session = SmtpSession::new(&hostname, &remote_address);
                session.set_submission_mode(true);
                session.set_tls_available(self.tls_available);
                session.set_accounts(self.accounts.clone());
                let greeting = session.greeting();
                (ProtocolState::SmtpSubmission(session), Some(greeting))
            }
            993 => {
                // IMAPS with implicit TLS (port 993)
                if let Some(ref resolver) = self.sni_resolver {
                    match TlsSession::new_with_sni_resolver(resolver.clone()) {
                        Ok(mut tls_session) => {
                            let handshake_data = tls_session.get_pending_ciphertext().ok();
                            let imap_session = ImapSession::new(&hostname, self.accounts.clone(), self.storage.clone(), true);
                            (
                                ProtocolState::ImapTls { tls_session, imap_session },
                                handshake_data.filter(|d| !d.is_empty()),
                            )
                        }
                        Err(e) => {
                            eprintln!("Failed to create TLS session for IMAPS: {}", e);
                            return (None, true);
                        }
                    }
                } else {
                    eprintln!("IMAPS (993) but no certificate available");
                    return (None, true);
                }
            }
            _ => (ProtocolState::Unknown, None),
        };

        self.connections.insert(
            connection_id,
            ConnectionInfo {
                connection_id,
                port,
                remote_address,
                protocol_state,
            },
        );

        (initial_response, false)
    }

    /// Remove a connection
    pub fn remove_connection(&mut self, connection_id: u64) {
        self.connections.remove(&connection_id);
    }

    /// Process incoming data for a connection
    /// Returns (response_data, should_close)
    pub fn process_data(&mut self, connection_id: u64, data: &[u8]) -> (Option<Vec<u8>>, bool) {
        let conn = match self.connections.get_mut(&connection_id) {
            Some(c) => c,
            None => return (None, false),
        };

        match &mut conn.protocol_state {
            ProtocolState::Outbound => {
                // Outbound connections are handled differently - data is passed through
                // This shouldn't normally be called directly
                (None, false)
            }
            ProtocolState::Smtp(session) => {
                let (response, should_close, start_tls, completed_transaction) = session.process_input(data);

                // Handle completed email
                if let Some(transaction) = completed_transaction {
                    if let Some(callback) = &self.on_email_received {
                        callback(transaction);
                    }
                }

                // Check if STARTTLS was requested
                if start_tls {
                    // We need to transition to SmtpTls state
                    // First send the response, then the connection manager needs to know
                    // to upgrade. We'll handle the upgrade by returning a flag.
                    let response_data = if response.is_empty() {
                        None
                    } else {
                        Some(response)
                    };
                    
                    // Return a special marker - the handler will call upgrade_to_tls
                    return (response_data, should_close);
                }

                let response_data = if response.is_empty() {
                    None
                } else {
                    Some(response)
                };

                (response_data, should_close)
            }
            ProtocolState::SmtpTls { tls_session, smtp_session } => {
                // SMTP over TLS - decrypt incoming data, process through SMTP, encrypt response
                
                // Process incoming ciphertext through TLS
                let plaintext = match tls_session.process_incoming(data) {
                    Ok(pt) => pt,
                    Err(e) => {
                        eprintln!("TLS error processing incoming SMTP data: {}", e);
                        return (None, true);
                    }
                };

                // Get any pending TLS handshake data
                let mut response_ciphertext = match tls_session.get_pending_ciphertext() {
                    Ok(ct) => ct,
                    Err(e) => {
                        eprintln!("TLS error getting pending ciphertext: {}", e);
                        return (None, true);
                    }
                };

                // If still handshaking, just return handshake data
                if tls_session.is_handshaking() {
                    if response_ciphertext.is_empty() {
                        return (None, false);
                    }
                    return (Some(response_ciphertext), false);
                }

                // Process decrypted SMTP data
                if !plaintext.is_empty() {
                    let (response, should_close, _start_tls, completed_transaction) = 
                        smtp_session.process_input(&plaintext);

                    // Handle completed email
                    if let Some(transaction) = completed_transaction {
                        if let Some(callback) = &self.on_email_received {
                            callback(transaction);
                        }
                    }

                    // Encrypt the SMTP response if any
                    if !response.is_empty() {
                        match tls_session.process_outgoing(&response) {
                            Ok(encrypted) => {
                                response_ciphertext.extend(encrypted);
                            }
                            Err(e) => {
                                eprintln!("TLS error encrypting SMTP response: {}", e);
                                return (None, true);
                            }
                        }
                    }

                    let response = if response_ciphertext.is_empty() {
                        None
                    } else {
                        Some(response_ciphertext)
                    };
                    return (response, should_close);
                }

                // Return handshake data if any
                if response_ciphertext.is_empty() {
                    (None, false)
                } else {
                    (Some(response_ciphertext), false)
                }
            }
            ProtocolState::Http(session) => {
                // Plain HTTP on port 80
                session.process_input(data)
            }
            ProtocolState::Https { tls_session, http_session } => {
                // HTTPS on port 443 - handle TLS unwrapping
                
                // Process incoming ciphertext through TLS
                let plaintext = match tls_session.process_incoming(data) {
                    Ok(pt) => pt,
                    Err(e) => {
                        eprintln!("TLS error processing incoming data: {}", e);
                        return (None, true);
                    }
                };

                // Get any pending TLS handshake data to send (server hello, etc.)
                let mut response_ciphertext = match tls_session.get_pending_ciphertext() {
                    Ok(ct) => ct,
                    Err(e) => {
                        eprintln!("TLS error getting pending ciphertext: {}", e);
                        return (None, true);
                    }
                };

                // If we're still handshaking, just return the handshake data
                if tls_session.is_handshaking() {
                    if response_ciphertext.is_empty() {
                        return (None, false);
                    }
                    return (Some(response_ciphertext), false);
                }

                // If we have decrypted HTTP data, process it
                if !plaintext.is_empty() {
                    let (http_response, should_close) = http_session.process_input(&plaintext);
                    
                    // Encrypt the HTTP response if any
                    if let Some(response_data) = http_response {
                        match tls_session.process_outgoing(&response_data) {
                            Ok(encrypted) => {
                                response_ciphertext.extend(encrypted);
                            }
                            Err(e) => {
                                eprintln!("TLS error encrypting response: {}", e);
                                return (None, true);
                            }
                        }
                    }
                    
                    let response = if response_ciphertext.is_empty() {
                        None
                    } else {
                        Some(response_ciphertext)
                    };
                    return (response, should_close);
                }

                // Return handshake data if any
                if response_ciphertext.is_empty() {
                    (None, false)
                } else {
                    (Some(response_ciphertext), false)
                }
            }
            ProtocolState::SmtpSubmission(session) => {
                // SMTP submission (port 587) - plaintext with STARTTLS
                let (response, should_close, start_tls, completed_transaction) = session.process_input(data);

                // Handle completed email
                if let Some(transaction) = completed_transaction {
                    if let Some(callback) = &self.on_email_received {
                        callback(transaction);
                    }
                }

                // Check if STARTTLS was requested
                if start_tls {
                    let response_data = if response.is_empty() {
                        None
                    } else {
                        Some(response)
                    };
                    return (response_data, should_close);
                }

                let response_data = if response.is_empty() {
                    None
                } else {
                    Some(response)
                };

                (response_data, should_close)
            }
            ProtocolState::SmtpSubmissionTls { tls_session, smtp_session } => {
                // SMTP submission over TLS (port 465 or 587 after STARTTLS)
                
                // Process incoming ciphertext through TLS
                let plaintext = match tls_session.process_incoming(data) {
                    Ok(pt) => pt,
                    Err(e) => {
                        eprintln!("TLS error processing incoming submission data: {}", e);
                        return (None, true);
                    }
                };

                // Get any pending TLS handshake data
                let mut response_ciphertext = match tls_session.get_pending_ciphertext() {
                    Ok(ct) => ct,
                    Err(e) => {
                        eprintln!("TLS error getting pending ciphertext: {}", e);
                        return (None, true);
                    }
                };

                // If still handshaking, just return handshake data
                if tls_session.is_handshaking() {
                    if response_ciphertext.is_empty() {
                        return (None, false);
                    }
                    return (Some(response_ciphertext), false);
                }

                // If handshake just completed and no banner sent yet, send greeting
                if !plaintext.is_empty() || !smtp_session.has_sent_greeting() {
                    // Send greeting if not sent
                    if !smtp_session.has_sent_greeting() {
                        let greeting = smtp_session.greeting();
                        match tls_session.process_outgoing(&greeting) {
                            Ok(encrypted) => {
                                response_ciphertext.extend(encrypted);
                            }
                            Err(e) => {
                                eprintln!("TLS error encrypting greeting: {}", e);
                                return (None, true);
                            }
                        }
                    }
                }

                // Process decrypted SMTP data
                if !plaintext.is_empty() {
                    let (response, should_close, _start_tls, completed_transaction) = 
                        smtp_session.process_input(&plaintext);

                    // Handle completed email
                    if let Some(transaction) = completed_transaction {
                        if let Some(callback) = &self.on_email_received {
                            callback(transaction);
                        }
                    }

                    // Encrypt the SMTP response if any
                    if !response.is_empty() {
                        match tls_session.process_outgoing(&response) {
                            Ok(encrypted) => {
                                response_ciphertext.extend(encrypted);
                            }
                            Err(e) => {
                                eprintln!("TLS error encrypting submission response: {}", e);
                                return (None, true);
                            }
                        }
                    }

                    let response = if response_ciphertext.is_empty() {
                        None
                    } else {
                        Some(response_ciphertext)
                    };
                    return (response, should_close);
                }

                // Return handshake data if any
                if response_ciphertext.is_empty() {
                    (None, false)
                } else {
                    (Some(response_ciphertext), false)
                }
            }
            ProtocolState::Imap(session) => {
                // IMAP (port 143) - plaintext with STARTTLS
                let (response, should_close, _start_tls) = session.process_input(data);

                let response_data = if response.is_empty() {
                    None
                } else {
                    Some(response)
                };

                (response_data, should_close)
            }
            ProtocolState::ImapTls { tls_session, imap_session } => {
                // IMAP over TLS (port 993 or after STARTTLS)
                
                // Process incoming ciphertext through TLS
                let plaintext = match tls_session.process_incoming(data) {
                    Ok(pt) => pt,
                    Err(e) => {
                        eprintln!("TLS error processing incoming IMAP data: {}", e);
                        return (None, true);
                    }
                };

                // Get any pending TLS handshake data
                let mut response_ciphertext = match tls_session.get_pending_ciphertext() {
                    Ok(ct) => ct,
                    Err(e) => {
                        eprintln!("TLS error getting pending ciphertext: {}", e);
                        return (None, true);
                    }
                };

                // If still handshaking, just return handshake data
                if tls_session.is_handshaking() {
                    if response_ciphertext.is_empty() {
                        return (None, false);
                    }
                    return (Some(response_ciphertext), false);
                }

                // If handshake just completed and no greeting sent yet, send greeting
                if !imap_session.has_sent_greeting() {
                    let greeting = imap_session.greeting();
                    match tls_session.process_outgoing(&greeting) {
                        Ok(encrypted) => {
                            response_ciphertext.extend(encrypted);
                        }
                        Err(e) => {
                            eprintln!("TLS error encrypting IMAP greeting: {}", e);
                            return (None, true);
                        }
                    }
                }

                // Process decrypted IMAP data
                if !plaintext.is_empty() {
                    let (response, should_close, _start_tls) = imap_session.process_input(&plaintext);

                    // Encrypt the IMAP response if any
                    if !response.is_empty() {
                        match tls_session.process_outgoing(&response) {
                            Ok(encrypted) => {
                                response_ciphertext.extend(encrypted);
                            }
                            Err(e) => {
                                eprintln!("TLS error encrypting IMAP response: {}", e);
                                return (None, true);
                            }
                        }
                    }

                    let response = if response_ciphertext.is_empty() {
                        None
                    } else {
                        Some(response_ciphertext)
                    };
                    return (response, should_close);
                }

                // Return handshake/greeting data if any
                if response_ciphertext.is_empty() {
                    (None, false)
                } else {
                    (Some(response_ciphertext), false)
                }
            }
            ProtocolState::Unknown => {
                // For unknown protocols, just echo what we received
                let text = String::from_utf8_lossy(data);
                println!(
                    "Unknown protocol data on connection {}: {}",
                    connection_id,
                    text.trim()
                );
                (Some(b"hello world\r\n".to_vec()), true)
            }
        }
    }

    /// Handle response to an outbound connection request
    pub async fn handle_outbound_connect_response(
        &mut self,
        connection_id: u64,
        success: bool,
        error: &str,
    ) {
        if let Some(pending) = self.pending_outbound.remove(&connection_id) {
            let result = if success {
                Ok(())
            } else {
                Err(error.to_string())
            };
            let _ = pending.result_tx.send(result);
        }
    }

    /// Register a pending outbound connection request
    pub fn register_outbound_pending(
        &mut self,
        connection_id: u64,
        result_tx: oneshot::Sender<Result<(), String>>,
    ) {
        self.pending_outbound.insert(connection_id, PendingOutbound { result_tx });
    }

    /// Register an established outbound connection
    pub fn register_outbound_connection(&mut self, connection_id: u64, remote_address: String) {
        self.connections.insert(
            connection_id,
            ConnectionInfo {
                connection_id,
                port: 0, // Outbound doesn't have a fixed port
                remote_address,
                protocol_state: ProtocolState::Outbound,
            },
        );
    }

    /// Check if a connection is waiting for TLS upgrade (after STARTTLS)
    pub fn needs_tls_upgrade(&self, connection_id: u64) -> bool {
        if let Some(conn) = self.connections.get(&connection_id) {
            if let ProtocolState::Smtp(session) = &conn.protocol_state {
                return session.state == crate::client::smtp::SmtpState::StartTls;
            }
        }
        false
    }

    /// Upgrade an SMTP connection to TLS after STARTTLS
    /// Returns true on success, false on error
    pub fn upgrade_smtp_to_tls(&mut self, connection_id: u64) -> bool {
        let cert = match self.certificate.as_ref() {
            Some(c) => c,
            None => {
                eprintln!("STARTTLS upgrade failed: No certificate available");
                return false;
            }
        };
        
        let conn = match self.connections.get_mut(&connection_id) {
            Some(c) => c,
            None => {
                eprintln!("STARTTLS upgrade failed: Connection {} not found", connection_id);
                return false;
            }
        };
        
        // Only upgrade if we're in the right state
        if let ProtocolState::Smtp(smtp_session) = &mut conn.protocol_state {
            if smtp_session.state != crate::client::smtp::SmtpState::StartTls {
                eprintln!("STARTTLS upgrade failed: Connection {} not in StartTls state (state: {:?})", 
                    connection_id, smtp_session.state);
                return false;
            }
            
            // Create TLS session
            let tls_session = match TlsSession::new(cert) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("STARTTLS upgrade failed: Failed to create TLS session: {}", e);
                    return false;
                }
            };

            // Clone the SMTP session and mark TLS handshake completed
            let mut new_smtp_session = smtp_session.clone();
            new_smtp_session.tls_handshake_completed();
            
            // Update protocol state to SmtpTls
            conn.protocol_state = ProtocolState::SmtpTls {
                tls_session,
                smtp_session: new_smtp_session,
            };
            
            println!("STARTTLS upgrade successful for connection {}", connection_id);
            true
        } else {
            eprintln!("STARTTLS upgrade failed: Connection {} is not in SMTP protocol state", connection_id);
            false
        }
    }

    /// Get connection info
    pub fn get_connection(&self, connection_id: u64) -> Option<&ConnectionInfo> {
        self.connections.get(&connection_id)
    }

    /// Check if a connection exists
    pub fn has_connection(&self, connection_id: u64) -> bool {
        self.connections.contains_key(&connection_id)
    }
}

/// Thread-safe connection manager
pub type SharedConnectionManager = Arc<RwLock<ConnectionManager>>;
