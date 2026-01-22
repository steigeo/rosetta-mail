/// Outbound email sender
/// 
/// Handles sending emails to external servers via the tunnel

use crate::client::smtp::MailTransaction;
use crate::client::smtp::security::{OutboundSecurityChecker, SecurityPolicy};
use crate::client::tls::dkim::DkimKeyPair;
use crate::proto::{tunnel_message::Payload, Data, OutboundConnectRequest, CloseConnection, TunnelMessage};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncBufReadExt, AsyncWriteExt, BufReader, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use hickory_resolver::TokioResolver;

/// A pending outbound connection
pub struct PendingOutbound {
    /// Channel to notify connection established
    pub established_tx: Option<oneshot::Sender<Result<(), String>>>,
    /// Channel to send received data
    pub data_tx: mpsc::Sender<Vec<u8>>,
}

/// Shared state for pending connections (accessed by both sender and handler)
pub type SharedPendingConnections = Arc<RwLock<HashMap<u64, PendingOutbound>>>;

/// A stream that wraps a tunnel connection, implementing AsyncRead + AsyncWrite
/// This allows us to wrap it with TLS for STARTTLS support
pub struct TunnelStream {
    conn_id: u64,
    tunnel_tx: mpsc::Sender<TunnelMessage>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    read_buffer: Vec<u8>,
}

impl TunnelStream {
    pub fn new(
        conn_id: u64,
        tunnel_tx: mpsc::Sender<TunnelMessage>,
        data_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            conn_id,
            tunnel_tx,
            data_rx,
            read_buffer: Vec::new(),
        }
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered data
        if !self.read_buffer.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer[..to_copy]);
            self.read_buffer.drain(..to_copy);
            return Poll::Ready(Ok(()));
        }
        
        // Try to receive more data
        match Pin::new(&mut self.data_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buffer.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let msg = TunnelMessage {
            payload: Some(Payload::Data(Data {
                connection_id: self.conn_id,
                payload: buf.to_vec(),
            })),
        };
        
        // Try to send (this is a bit tricky with async in poll context)
        // We need to use try_send or create a future
        match self.tunnel_tx.try_send(msg) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full, register waker and return pending
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "tunnel closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Outbound email sender
pub struct OutboundSender {
    /// DKIM keypair for signing
    dkim_keypair: Option<Arc<DkimKeyPair>>,
    /// Mail domain for DKIM signing
    mail_domain: String,
    /// DKIM selector
    dkim_selector: String,
    /// Hostname for EHLO
    hostname: String,
    /// Channel to send messages to tunnel server
    tunnel_tx: mpsc::Sender<TunnelMessage>,
    /// DNS resolver for MX lookups
    resolver: TokioResolver,
    /// Next connection ID (protected by mutex for thread safety)
    next_conn_id: Arc<Mutex<u64>>,
    /// Pending outbound connections (shared with handler)
    pending_connections: SharedPendingConnections,
    /// Security policy checker (MTA-STS + DANE)
    security_checker: OutboundSecurityChecker,
}

impl OutboundSender {
    pub fn new(
        dkim_keypair: Option<Arc<DkimKeyPair>>,
        mail_domain: String,
        hostname: String,
        tunnel_tx: mpsc::Sender<TunnelMessage>,
    ) -> Result<Self, String> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| format!("Failed to create resolver: {}", e))?
            .build();
        
        Ok(Self {
            dkim_keypair,
            mail_domain,
            dkim_selector: "dkim".to_string(),
            hostname,
            tunnel_tx,
            resolver,
            next_conn_id: Arc::new(Mutex::new(0x8000_0000_0000_0000)), // Start high to avoid collision with inbound IDs
            pending_connections: Arc::new(RwLock::new(HashMap::new())),
            security_checker: OutboundSecurityChecker::new(),
        })
    }

    /// Send an outbound email
    pub async fn send(&self, transaction: &MailTransaction) -> Result<(), String> {
        // Sign with DKIM if we have a keypair
        let email_data = if let Some(ref dkim) = self.dkim_keypair {
            match dkim.sign(&transaction.data, &self.dkim_selector, &self.mail_domain) {
                Ok(signed) => {
                    println!("  DKIM signed email, new size: {}", signed.len());
                    signed
                }
                Err(e) => {
                    eprintln!("  Warning: DKIM signing failed: {}", e);
                    transaction.data.clone()
                }
            }
        } else {
            println!("  Warning: No DKIM keypair, sending unsigned");
            transaction.data.clone()
        };

        // Group recipients by domain
        let mut by_domain: HashMap<String, Vec<String>> = HashMap::new();
        for rcpt in &transaction.rcpt_to {
            if let Some(domain) = rcpt.split('@').last() {
                by_domain.entry(domain.to_lowercase()).or_default().push(rcpt.clone());
            }
        }

        // Send to each domain
        let mut errors = Vec::new();
        for (domain, recipients) in by_domain {
            println!("  Sending to domain: {} ({} recipients)", domain, recipients.len());
            
            if let Err(e) = self.send_to_domain(&domain, &transaction.mail_from, &recipients, &email_data).await {
                errors.push(format!("{}: {}", domain, e));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Send to a specific domain
    async fn send_to_domain(
        &self,
        domain: &str,
        mail_from: &str,
        recipients: &[String],
        email_data: &[u8],
    ) -> Result<(), String> {
        // Look up MX records
        let mx_hosts = self.lookup_mx(domain).await?;
        
        println!("    MX records for {}: {:?}", domain, mx_hosts);

        if mx_hosts.is_empty() {
            // No MX, try A record (domain itself)
            let policy = self.security_checker.get_policy(domain, domain, 25).await;
            return self.try_send_to_host(domain, 25, mail_from, recipients, email_data, &policy).await;
        }

        // Try each MX in order
        let mut last_error = String::new();
        for mx_host in mx_hosts {
            // Get security policy for this domain/MX combination
            let policy = self.security_checker.get_policy(domain, &mx_host, 25).await;
            
            // Check MTA-STS MX validation
            if let Some(ref valid_hosts) = policy.valid_mx_hosts {
                let mx_lower = mx_host.to_lowercase();
                let mut mx_valid = false;
                for allowed in valid_hosts {
                    if allowed.starts_with("*.") {
                        let suffix = &allowed[1..];
                        if mx_lower.ends_with(suffix) || mx_lower == allowed[2..] {
                            mx_valid = true;
                            break;
                        }
                    } else if mx_lower == *allowed {
                        mx_valid = true;
                        break;
                    }
                }
                if !mx_valid {
                    println!("    MTA-STS: Skipping MX {} (not in policy)", mx_host);
                    last_error = format!("MX host {} not allowed by MTA-STS policy", mx_host);
                    continue;
                }
            }
            
            match self.try_send_to_host(&mx_host, 25, mail_from, recipients, email_data, &policy).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    println!("    Failed to send to {}: {}", mx_host, e);
                    last_error = e;
                }
            }
        }

        Err(format!("All MX hosts failed, last error: {}", last_error))
    }

    /// Look up MX records for a domain
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<String>, String> {
        match self.resolver.mx_lookup(domain).await {
            Ok(response) => {
                let mut records: Vec<(u16, String)> = Vec::new();
                for mx in response.iter() {
                    records.push((mx.preference(), mx.exchange().to_string().trim_end_matches('.').to_string()));
                }
                
                // Sort by preference (lower is better)
                records.sort_by_key(|(pref, _)| *pref);
                
                Ok(records.into_iter().map(|(_, host)| host).collect())
            }
            Err(e) => {
                // No MX records, return empty (caller will try A record)
                println!("    No MX records for {}: {}", domain, e);
                Ok(vec![])
            }
        }
    }

    /// Try to send to a specific host
    async fn try_send_to_host(
        &self,
        host: &str,
        port: u16,
        mail_from: &str,
        recipients: &[String],
        email_data: &[u8],
        security_policy: &SecurityPolicy,
    ) -> Result<(), String> {
        println!("    Connecting to {}:{}...", host, port);
        println!("    Security: require_tls={}, dane_records={}, dane_validated={}", 
                 security_policy.require_tls, 
                 security_policy.tlsa_records.len(),
                 security_policy.dane_validated);

        // Allocate connection ID
        let conn_id = {
            let mut id = self.next_conn_id.lock().await;
            let current = *id;
            *id += 1;
            current
        };

        // Create channels for this connection
        let (established_tx, established_rx) = oneshot::channel();
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(100);

        // Register the pending connection
        {
            let mut pending = self.pending_connections.write().await;
            pending.insert(conn_id, PendingOutbound {
                established_tx: Some(established_tx),
                data_tx,
            });
        }

        // Request outbound connection
        let connect_req = TunnelMessage {
            payload: Some(Payload::OutboundConnectRequest(OutboundConnectRequest {
                connection_id: conn_id,
                host: host.to_string(),
                port: port as u32,
            })),
        };

        self.tunnel_tx.send(connect_req).await
            .map_err(|e| format!("Failed to send connect request: {}", e))?;

        // Wait for connection to be established (with timeout)
        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            established_rx
        ).await
            .map_err(|_| "Connection timeout".to_string())?
            .map_err(|_| "Connection channel closed".to_string())?;

        connect_result?;

        println!("    Connected to {}:{}", host, port);

        // Create tunnel stream
        let stream = TunnelStream::new(conn_id, self.tunnel_tx.clone(), data_rx);
        
        // Perform SMTP conversation (with optional STARTTLS)
        let result = self.smtp_conversation(stream, mail_from, recipients, email_data, host, security_policy).await;

        // Close the connection
        let close_msg = TunnelMessage {
            payload: Some(Payload::CloseConnection(CloseConnection {
                connection_id: conn_id,
            })),
        };
        let _ = self.tunnel_tx.send(close_msg).await;

        // Clean up
        {
            let mut pending = self.pending_connections.write().await;
            pending.remove(&conn_id);
        }

        result
    }

    /// Perform SMTP conversation with optional STARTTLS
    async fn smtp_conversation<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        mail_from: &str,
        recipients: &[String],
        email_data: &[u8],
        hostname: &str,
        security_policy: &SecurityPolicy,
    ) -> Result<(), String> {
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};
        use tokio_rustls::rustls::pki_types::ServerName;
        
        let mut reader = BufReader::new(stream);
        
        // Read greeting
        let greeting = read_line(&mut reader).await?;
        println!("    < {}", greeting);
        if !greeting.starts_with("220") {
            return Err(format!("Bad greeting: {}", greeting));
        }

        // Send EHLO
        write_line(&mut reader, &format!("EHLO {}", self.hostname)).await?;
        println!("    > EHLO {}", self.hostname);
        
        // Read EHLO response (may be multiline) and check for STARTTLS
        let mut has_starttls = false;
        loop {
            let line = read_line(&mut reader).await?;
            println!("    < {}", line);
            
            // Check for STARTTLS capability
            if line.to_uppercase().contains("STARTTLS") {
                has_starttls = true;
            }
            
            if line.len() >= 4 && line.chars().nth(3) == Some(' ') {
                if !line.starts_with("250") {
                    return Err(format!("EHLO rejected: {}", line));
                }
                break;
            }
        }

        // Check if TLS is required by policy
        if security_policy.require_tls && !has_starttls {
            return Err("TLS required by security policy but server does not support STARTTLS".to_string());
        }

        // If STARTTLS is offered, upgrade the connection
        if has_starttls {
            println!("    Server offers STARTTLS, upgrading connection...");
            
            // Send STARTTLS command
            write_line(&mut reader, "STARTTLS").await?;
            println!("    > STARTTLS");
            
            let starttls_resp = read_line(&mut reader).await?;
            println!("    < {}", starttls_resp);
            
            if !starttls_resp.starts_with("220") {
                if security_policy.require_tls {
                    return Err(format!("TLS required by policy but STARTTLS failed: {}", starttls_resp));
                }
                println!("    Warning: STARTTLS not accepted: {}", starttls_resp);
                // Continue without TLS
                return self.smtp_send_mail(reader, mail_from, recipients, email_data).await;
            }
            
            // Perform TLS handshake on the client side (end-to-end encryption)
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            
            // For DANE-EE (usage 3), we may need to skip CA verification
            // and only verify the certificate against TLSA records
            let has_dane_ee = security_policy.tlsa_records.iter()
                .any(|r| r.usage == 3);
            
            let config = if has_dane_ee {
                // DANE-EE: Trust the certificate if it matches TLSA record
                // Use dangerous configuration that accepts any certificate
                // We'll verify against TLSA records manually
                use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
                use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};
                use tokio_rustls::rustls::pki_types::{CertificateDer, UnixTime};
                
                #[derive(Debug)]
                struct DaneCertVerifier;
                
                impl ServerCertVerifier for DaneCertVerifier {
                    fn verify_server_cert(
                        &self,
                        _end_entity: &CertificateDer<'_>,
                        _intermediates: &[CertificateDer<'_>],
                        _server_name: &ServerName<'_>,
                        _ocsp_response: &[u8],
                        _now: UnixTime,
                    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
                        // We'll verify against DANE records after handshake
                        Ok(ServerCertVerified::assertion())
                    }
                    
                    fn verify_tls12_signature(
                        &self,
                        _message: &[u8],
                        _cert: &CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                        Ok(HandshakeSignatureValid::assertion())
                    }
                    
                    fn verify_tls13_signature(
                        &self,
                        _message: &[u8],
                        _cert: &CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                        Ok(HandshakeSignatureValid::assertion())
                    }
                    
                    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                        vec![
                            SignatureScheme::RSA_PKCS1_SHA256,
                            SignatureScheme::RSA_PKCS1_SHA384,
                            SignatureScheme::RSA_PKCS1_SHA512,
                            SignatureScheme::ECDSA_NISTP256_SHA256,
                            SignatureScheme::ECDSA_NISTP384_SHA384,
                            SignatureScheme::ECDSA_NISTP521_SHA512,
                            SignatureScheme::RSA_PSS_SHA256,
                            SignatureScheme::RSA_PSS_SHA384,
                            SignatureScheme::RSA_PSS_SHA512,
                            SignatureScheme::ED25519,
                        ]
                    }
                }
                
                Arc::new(
                    ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(DaneCertVerifier))
                        .with_no_client_auth()
                )
            } else {
                Arc::new(
                    ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth()
                )
            };
            
            let connector = TlsConnector::from(config);
            
            let server_name = ServerName::try_from(hostname.to_string())
                .map_err(|e| format!("Invalid hostname: {}", e))?;
            
            // Get the inner stream from BufReader
            let inner_stream = reader.into_inner();
            
            let tls_stream = connector.connect(server_name, inner_stream).await
                .map_err(|e| format!("TLS handshake failed: {}", e))?;
            
            println!("    TLS handshake successful");
            
            // Verify DANE if we have TLSA records
            if !security_policy.tlsa_records.is_empty() {
                let (_, connection) = tls_stream.get_ref();
                if let Some(certs) = connection.peer_certificates() {
                    let cert_chain: Vec<_> = certs.to_vec();
                    if !self.security_checker.verify_dane(security_policy, &cert_chain) {
                        return Err("DANE certificate verification failed".to_string());
                    }
                } else if security_policy.require_tls {
                    return Err("No peer certificates available for DANE verification".to_string());
                }
            }
            
            // Wrap in BufReader again
            let mut tls_reader = BufReader::new(tls_stream);
            
            // After TLS upgrade, need to send EHLO again
            write_line(&mut tls_reader, &format!("EHLO {}", self.hostname)).await?;
            println!("    > EHLO {}", self.hostname);
            
            // Read new EHLO response
            loop {
                let line = read_line(&mut tls_reader).await?;
                println!("    < {}", line);
                if line.len() >= 4 && line.chars().nth(3) == Some(' ') {
                    if !line.starts_with("250") {
                        return Err(format!("EHLO rejected after STARTTLS: {}", line));
                    }
                    break;
                }
            }
            
            // Continue with TLS stream
            return self.smtp_send_mail(tls_reader, mail_from, recipients, email_data).await;
        } else {
            println!("    Warning: Server does not offer STARTTLS, continuing unencrypted");
        }

        // Continue without TLS
        self.smtp_send_mail(reader, mail_from, recipients, email_data).await
    }
    
    /// Send the actual mail after connection is established (plain or TLS)
    async fn smtp_send_mail<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: BufReader<S>,
        mail_from: &str,
        recipients: &[String],
        email_data: &[u8],
    ) -> Result<(), String> {
        // MAIL FROM
        write_line(&mut stream, &format!("MAIL FROM:<{}>", mail_from)).await?;
        println!("    > MAIL FROM:<{}>", mail_from);
        let mail_resp = read_line(&mut stream).await?;
        println!("    < {}", mail_resp);
        if !mail_resp.starts_with("250") {
            return Err(format!("MAIL FROM rejected: {}", mail_resp));
        }

        // RCPT TO for each recipient
        for rcpt in recipients {
            write_line(&mut stream, &format!("RCPT TO:<{}>", rcpt)).await?;
            println!("    > RCPT TO:<{}>", rcpt);
            let rcpt_resp = read_line(&mut stream).await?;
            println!("    < {}", rcpt_resp);
            if !rcpt_resp.starts_with("250") {
                println!("    Warning: RCPT TO rejected for {}: {}", rcpt, rcpt_resp);
            }
        }

        // DATA
        write_line(&mut stream, "DATA").await?;
        println!("    > DATA");
        let data_resp = read_line(&mut stream).await?;
        println!("    < {}", data_resp);
        if !data_resp.starts_with("354") {
            return Err(format!("DATA rejected: {}", data_resp));
        }

        // Send the email data with dot-stuffing
        let email_str = String::from_utf8_lossy(email_data);
        for line in email_str.lines() {
            if line.starts_with('.') {
                stream.get_mut().write_all(b".").await.map_err(|e| e.to_string())?;
            }
            stream.get_mut().write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;
            stream.get_mut().write_all(b"\r\n").await.map_err(|e| e.to_string())?;
        }
        stream.get_mut().write_all(b".\r\n").await.map_err(|e| e.to_string())?;
        stream.get_mut().flush().await.map_err(|e| e.to_string())?;
        println!("    > [email data, {} bytes]", email_data.len());

        // Read DATA response
        let final_resp = read_line(&mut stream).await?;
        println!("    < {}", final_resp);
        if !final_resp.starts_with("250") {
            return Err(format!("Message rejected: {}", final_resp));
        }

        // QUIT
        write_line(&mut stream, "QUIT").await?;
        println!("    > QUIT");

        println!("    Email sent successfully!");
        Ok(())
    }

    /// Handle connection established notification from tunnel
    pub async fn handle_connect_response(&self, conn_id: u64, success: bool, error: &str) {
        let mut pending = self.pending_connections.write().await;
        if let Some(conn) = pending.get_mut(&conn_id) {
            if let Some(tx) = conn.established_tx.take() {
                let result = if success { Ok(()) } else { Err(error.to_string()) };
                let _ = tx.send(result);
            }
        }
    }

    /// Handle data received on an outbound connection
    pub async fn handle_data(&self, conn_id: u64, data: &[u8]) {
        let pending = self.pending_connections.read().await;
        if let Some(conn) = pending.get(&conn_id) {
            let _ = conn.data_tx.send(data.to_vec()).await;
        }
    }

    /// Check if a connection ID belongs to us (outbound)
    pub fn is_outbound_connection(&self, conn_id: u64) -> bool {
        conn_id >= 0x8000_0000_0000_0000
    }

    /// Get the pending connections map for external access (e.g., from handler)
    pub fn get_pending_connections(&self) -> SharedPendingConnections {
        self.pending_connections.clone()
    }
}

/// Helper to read a line from an async reader
async fn read_line<S: AsyncRead + Unpin>(reader: &mut BufReader<S>) -> Result<String, String> {
    let mut line = String::new();
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.read_line(&mut line)
    ).await {
        Ok(Ok(0)) => Err("Connection closed".to_string()),
        Ok(Ok(_)) => Ok(line.trim_end().to_string()),
        Ok(Err(e)) => Err(format!("Read error: {}", e)),
        Err(_) => Err("Read timeout".to_string()),
    }
}

/// Helper to write a line to an async writer
async fn write_line<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    line: &str,
) -> Result<(), String> {
    reader.get_mut().write_all(format!("{}\r\n", line).as_bytes()).await
        .map_err(|e| format!("Write error: {}", e))?;
    reader.get_mut().flush().await
        .map_err(|e| format!("Flush error: {}", e))
}
