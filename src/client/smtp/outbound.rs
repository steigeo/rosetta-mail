/// Outbound SMTP client for sending emails

use std::io::{BufRead, BufReader, Read, Write};

/// SMTP client for outbound mail delivery
pub struct SmtpClient<S: Read + Write> {
    stream: BufReader<S>,
    writer: S,
    hostname: String,
}

/// Result of an SMTP operation
#[derive(Debug)]
pub struct SmtpReply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl SmtpReply {
    pub fn is_positive(&self) -> bool {
        self.code >= 200 && self.code < 400
    }
    
    pub fn is_2xx(&self) -> bool {
        self.code >= 200 && self.code < 300
    }
    
    pub fn is_3xx(&self) -> bool {
        self.code >= 300 && self.code < 400
    }
}

/// Error type for SMTP client operations
#[derive(Debug)]
pub enum SmtpClientError {
    Io(std::io::Error),
    InvalidReply(String),
    Rejected(SmtpReply),
    ConnectionClosed,
}

impl std::fmt::Display for SmtpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::InvalidReply(s) => write!(f, "Invalid SMTP reply: {}", s),
            Self::Rejected(reply) => write!(f, "Rejected: {} {}", reply.code, reply.lines.join(" ")),
            Self::ConnectionClosed => write!(f, "Connection closed unexpectedly"),
        }
    }
}

impl std::error::Error for SmtpClientError {}

impl From<std::io::Error> for SmtpClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl<S: Read + Write + Clone> SmtpClient<S> {
    /// Create a new SMTP client wrapping an existing stream
    pub fn new(stream: S, hostname: &str) -> Self {
        Self {
            stream: BufReader::new(stream.clone()),
            writer: stream,
            hostname: hostname.to_string(),
        }
    }

    /// Read an SMTP reply (possibly multiline)
    pub fn read_reply(&mut self) -> Result<SmtpReply, SmtpClientError> {
        let mut lines = Vec::new();
        let mut code: u16 = 0;

        loop {
            let mut line = String::new();
            let n = self.stream.read_line(&mut line)?;
            if n == 0 {
                return Err(SmtpClientError::ConnectionClosed);
            }

            // Parse reply code
            if line.len() < 4 {
                return Err(SmtpClientError::InvalidReply(line));
            }

            let reply_code: u16 = line[..3].parse()
                .map_err(|_| SmtpClientError::InvalidReply(line.clone()))?;
            
            if code == 0 {
                code = reply_code;
            } else if code != reply_code {
                return Err(SmtpClientError::InvalidReply(format!(
                    "Inconsistent reply codes: {} vs {}", code, reply_code
                )));
            }

            let separator = line.chars().nth(3).unwrap_or(' ');
            let text = line[4..].trim_end().to_string();
            lines.push(text);

            // Space separator means last line
            if separator == ' ' {
                break;
            }
        }

        Ok(SmtpReply { code, lines })
    }

    /// Send a command and wait for reply
    pub fn command(&mut self, cmd: &str) -> Result<SmtpReply, SmtpClientError> {
        write!(self.writer, "{}\r\n", cmd)?;
        self.writer.flush()?;
        self.read_reply()
    }

    /// Read the initial greeting from the server
    pub fn read_greeting(&mut self) -> Result<SmtpReply, SmtpClientError> {
        self.read_reply()
    }

    /// Send EHLO command
    pub fn ehlo(&mut self) -> Result<SmtpReply, SmtpClientError> {
        self.command(&format!("EHLO {}", self.hostname))
    }

    /// Send MAIL FROM command
    pub fn mail_from(&mut self, address: &str) -> Result<SmtpReply, SmtpClientError> {
        self.command(&format!("MAIL FROM:<{}>", address))
    }

    /// Send RCPT TO command
    pub fn rcpt_to(&mut self, address: &str) -> Result<SmtpReply, SmtpClientError> {
        self.command(&format!("RCPT TO:<{}>", address))
    }

    /// Send DATA command and then the message body
    pub fn data(&mut self, body: &[u8]) -> Result<SmtpReply, SmtpClientError> {
        // Send DATA command
        let reply = self.command("DATA")?;
        if !reply.is_3xx() {
            return Err(SmtpClientError::Rejected(reply));
        }

        // Send the message body with dot-stuffing
        let body_str = String::from_utf8_lossy(body);
        for line in body_str.lines() {
            if line.starts_with('.') {
                write!(self.writer, ".{}\r\n", line)?;
            } else {
                write!(self.writer, "{}\r\n", line)?;
            }
        }

        // Send the terminating dot
        write!(self.writer, ".\r\n")?;
        self.writer.flush()?;

        self.read_reply()
    }

    /// Send STARTTLS command
    pub fn starttls(&mut self) -> Result<SmtpReply, SmtpClientError> {
        self.command("STARTTLS")
    }

    /// Send QUIT command
    pub fn quit(&mut self) -> Result<SmtpReply, SmtpClientError> {
        self.command("QUIT")
    }

    /// Check if EHLO response advertises a capability
    pub fn has_capability(reply: &SmtpReply, capability: &str) -> bool {
        reply.lines.iter().any(|line| {
            line.to_uppercase().starts_with(&capability.to_uppercase())
        })
    }
}

/// Async wrapper for outbound SMTP over a tokio stream
pub mod async_client {
    use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
    use super::{SmtpReply, SmtpClientError};

    /// Async SMTP client for outbound mail delivery
    pub struct AsyncSmtpClient<S: AsyncRead + AsyncWrite + Unpin> {
        reader: BufReader<tokio::io::ReadHalf<S>>,
        writer: tokio::io::WriteHalf<S>,
        hostname: String,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncSmtpClient<S> {
        /// Create a new async SMTP client
        pub fn new(stream: S, hostname: &str) -> Self {
            let (reader, writer) = tokio::io::split(stream);
            Self {
                reader: BufReader::new(reader),
                writer,
                hostname: hostname.to_string(),
            }
        }

        /// Read an SMTP reply (possibly multiline)
        pub async fn read_reply(&mut self) -> Result<SmtpReply, SmtpClientError> {
            let mut lines = Vec::new();
            let mut code: u16 = 0;

            loop {
                let mut line = String::new();
                let n = self.reader.read_line(&mut line).await?;
                if n == 0 {
                    return Err(SmtpClientError::ConnectionClosed);
                }

                // Parse reply code
                if line.len() < 4 {
                    return Err(SmtpClientError::InvalidReply(line));
                }

                let reply_code: u16 = line[..3].parse()
                    .map_err(|_| SmtpClientError::InvalidReply(line.clone()))?;
                
                if code == 0 {
                    code = reply_code;
                } else if code != reply_code {
                    return Err(SmtpClientError::InvalidReply(format!(
                        "Inconsistent reply codes: {} vs {}", code, reply_code
                    )));
                }

                let separator = line.chars().nth(3).unwrap_or(' ');
                let text = line[4..].trim_end().to_string();
                lines.push(text);

                // Space separator means last line
                if separator == ' ' {
                    break;
                }
            }

            Ok(SmtpReply { code, lines })
        }

        /// Send a command and wait for reply
        pub async fn command(&mut self, cmd: &str) -> Result<SmtpReply, SmtpClientError> {
            self.writer.write_all(format!("{}\r\n", cmd).as_bytes()).await?;
            self.writer.flush().await?;
            self.read_reply().await
        }

        /// Read the initial greeting from the server
        pub async fn read_greeting(&mut self) -> Result<SmtpReply, SmtpClientError> {
            self.read_reply().await
        }

        /// Send EHLO command
        pub async fn ehlo(&mut self) -> Result<SmtpReply, SmtpClientError> {
            self.command(&format!("EHLO {}", self.hostname)).await
        }

        /// Send MAIL FROM command
        pub async fn mail_from(&mut self, address: &str) -> Result<SmtpReply, SmtpClientError> {
            self.command(&format!("MAIL FROM:<{}>", address)).await
        }

        /// Send RCPT TO command
        pub async fn rcpt_to(&mut self, address: &str) -> Result<SmtpReply, SmtpClientError> {
            self.command(&format!("RCPT TO:<{}>", address)).await
        }

        /// Send DATA command and then the message body
        pub async fn data(&mut self, body: &[u8]) -> Result<SmtpReply, SmtpClientError> {
            // Send DATA command
            let reply = self.command("DATA").await?;
            if !reply.is_3xx() {
                return Err(SmtpClientError::Rejected(reply));
            }

            // Send the message body with dot-stuffing
            let body_str = String::from_utf8_lossy(body);
            for line in body_str.lines() {
                if line.starts_with('.') {
                    self.writer.write_all(format!(".{}\r\n", line).as_bytes()).await?;
                } else {
                    self.writer.write_all(format!("{}\r\n", line).as_bytes()).await?;
                }
            }

            // Send the terminating dot
            self.writer.write_all(b".\r\n").await?;
            self.writer.flush().await?;

            self.read_reply().await
        }

        /// Send STARTTLS command
        pub async fn starttls(&mut self) -> Result<SmtpReply, SmtpClientError> {
            self.command("STARTTLS").await
        }

        /// Send QUIT command
        pub async fn quit(&mut self) -> Result<SmtpReply, SmtpClientError> {
            self.command("QUIT").await
        }

        /// Check if EHLO response advertises a capability
        pub fn has_capability(reply: &SmtpReply, capability: &str) -> bool {
            reply.lines.iter().any(|line| {
                line.to_uppercase().starts_with(&capability.to_uppercase())
            })
        }
        
        /// Get inner stream parts (for TLS upgrade)
        pub fn into_parts(self) -> (BufReader<tokio::io::ReadHalf<S>>, tokio::io::WriteHalf<S>) {
            (self.reader, self.writer)
        }
    }
}
