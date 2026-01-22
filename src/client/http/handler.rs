use super::mta_sts::MtaStsPolicy;

/// HTTP/HTTPS session for handling web requests
/// This handles incoming connections on ports 80 and 443
pub struct HttpSession {
    /// Whether this is a TLS connection (port 443)
    pub is_tls: bool,
    /// MTA-STS policy to serve
    pub mta_sts_policy: Option<MtaStsPolicy>,
    /// Hostname for this server
    pub hostname: String,
    /// Mail domain
    pub mail_domain: String,
    /// Buffer for incoming data
    buffer: Vec<u8>,
    /// Whether we've processed the request
    request_complete: bool,
}

impl HttpSession {
    pub fn new(hostname: &str, mail_domain: &str, is_tls: bool) -> Self {
        let mta_sts_policy = Some(MtaStsPolicy::new(hostname.to_string(), mail_domain.to_string()));
        Self {
            is_tls,
            mta_sts_policy,
            hostname: hostname.to_string(),
            mail_domain: mail_domain.to_string(),
            buffer: Vec::new(),
            request_complete: false,
        }
    }

    /// Process incoming HTTP data
    /// Returns (response_data, should_close)
    pub fn process_input(&mut self, data: &[u8]) -> (Option<Vec<u8>>, bool) {
        // For TLS connections, we need to handle TLS first
        // For now, this handles plaintext HTTP
        
        self.buffer.extend_from_slice(data);

        // Look for end of HTTP headers (double CRLF)
        if let Some(pos) = find_header_end(&self.buffer) {
            let request = String::from_utf8_lossy(&self.buffer[..pos]).to_string();
            self.buffer.drain(..pos + 4); // Remove headers including \r\n\r\n

            let response = self.handle_request(&request);
            self.request_complete = true;
            
            return (Some(response), true);
        }

        // Need more data
        (None, false)
    }

    /// Handle an HTTP request and return the response
    fn handle_request(&self, request: &str) -> Vec<u8> {
        let lines: Vec<&str> = request.lines().collect();
        if lines.is_empty() {
            return self.error_response(400, "Bad Request");
        }

        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return self.error_response(400, "Bad Request");
        }

        let method = parts[0];
        let path = parts[1];

        // Extract Host header
        let host = lines
            .iter()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim())
            .unwrap_or("");

        // Remove port from host if present
        let host_without_port = host.split(':').next().unwrap_or(host);

        println!("HTTP {} {} (Host: {})", method, path, host);

        // Only allow requests to mta-sts.<mail_domain>
        let expected_host = format!("mta-sts.{}", self.mail_domain);
        if !host_without_port.eq_ignore_ascii_case(&expected_host) {
            println!("  Rejected: Host '{}' != expected '{}'", host_without_port, expected_host);
            return self.error_response(404, "Not Found");
        }

        // Only handle GET requests
        if method != "GET" {
            return self.error_response(405, "Method Not Allowed");
        }

        // Only serve the MTA-STS policy path
        if path == "/.well-known/mta-sts.txt" {
            if self.is_tls {
                // HTTPS: serve the policy
                self.handle_mta_sts()
            } else {
                // HTTP: redirect to HTTPS
                let location = format!("https://{}/.well-known/mta-sts.txt", expected_host);
                self.redirect_response(&location)
            }
        } else {
            // All other paths return 404
            self.error_response(404, "Not Found")
        }
    }

    /// Handle MTA-STS policy request
    fn handle_mta_sts(&self) -> Vec<u8> {
        if let Some(ref policy) = self.mta_sts_policy {
            let body = policy.policy_text();
            self.ok_response("text/plain", &body)
        } else {
            self.error_response(404, "Not Found")
        }
    }

    /// Generate an OK response
    fn ok_response(&self, content_type: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            content_type,
            body.len(),
            body
        )
        .into_bytes()
    }

    /// Generate an error response
    fn error_response(&self, code: u16, message: &str) -> Vec<u8> {
        let body = format!("<html><body><h1>{} {}</h1></body></html>", code, message);
        format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: text/html\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            code,
            message,
            body.len(),
            body
        )
        .into_bytes()
    }

    /// Generate a redirect response
    fn redirect_response(&self, location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 301 Moved Permanently\r\n\
             Location: {}\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n",
            location
        )
        .into_bytes()
    }
}

/// Find the end of HTTP headers (double CRLF)
fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mta_sts_request() {
        let mut session = HttpSession::new("mail.example.com", "example.com", true);
        let request = b"GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.example.com\r\n\r\n";
        
        let (response, should_close) = session.process_input(request);
        
        assert!(should_close);
        let response = response.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("200 OK"));
        assert!(response_str.contains("version: STSv1"));
        assert!(response_str.contains("mail.example.com"));
    }

    #[test]
    fn test_http_redirect() {
        let mut session = HttpSession::new("mail.example.com", "example.com", false);
        let request = b"GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mta-sts.example.com\r\n\r\n";
        
        let (response, _) = session.process_input(request);
        
        let response = response.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("301 Moved Permanently"));
        assert!(response_str.contains("https://mta-sts.example.com/.well-known/mta-sts.txt"));
    }

    #[test]
    fn test_404_wrong_host() {
        let mut session = HttpSession::new("mail.example.com", "example.com", true);
        // Request to wrong host should return 404
        let request = b"GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: mail.example.com\r\n\r\n";
        
        let (response, _) = session.process_input(request);
        
        let response = response.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("404 Not Found"));
    }

    #[test]
    fn test_404_wrong_path() {
        let mut session = HttpSession::new("mail.example.com", "example.com", true);
        // Request to wrong path should return 404
        let request = b"GET /other-path HTTP/1.1\r\nHost: mta-sts.example.com\r\n\r\n";
        
        let (response, _) = session.process_input(request);
        
        let response = response.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("404 Not Found"));
    }
}
