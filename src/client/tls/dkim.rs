use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
    signature::{RandomizedSigner, SignatureEncoding},
    pkcs1v15::SigningKey,
};
use std::path::Path;
use tokio::fs;

const DKIM_KEY_SIZE: usize = 2048;

/// DKIM RSA key pair
pub struct DkimKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl DkimKeyPair {
    /// Generate a new DKIM key pair
    pub fn generate() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, DKIM_KEY_SIZE)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Load a DKIM key pair from storage, or generate a new one if not found
    pub async fn load_or_generate(
        storage_path: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let private_key_path = storage_path.join("dkim_private.pem");

        if private_key_path.exists() {
            println!("Loading existing DKIM key pair...");
            let private_pem = fs::read_to_string(&private_key_path).await?;
            let private_key = RsaPrivateKey::from_pkcs8_pem(&private_pem)?;
            let public_key = RsaPublicKey::from(&private_key);
            Ok(Self {
                private_key,
                public_key,
            })
        } else {
            println!("Generating new DKIM key pair...");
            let keypair = Self::generate()?;
            keypair.save(storage_path).await?;
            Ok(keypair)
        }
    }

    /// Save the key pair to storage
    pub async fn save(&self, storage_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        fs::create_dir_all(storage_path).await?;

        let private_key_path = storage_path.join("dkim_private.pem");
        let public_key_path = storage_path.join("dkim_public.pem");

        let private_pem = self.private_key.to_pkcs8_pem(LineEnding::LF)?;
        fs::write(&private_key_path, private_pem.as_bytes()).await?;

        let public_pem = self.public_key.to_pkcs1_pem(LineEnding::LF)?;
        fs::write(&public_key_path, public_pem).await?;

        println!("DKIM keys saved to {:?}", storage_path);
        Ok(())
    }

    /// Get the public key in base64 format for DNS TXT record
    /// Uses SubjectPublicKeyInfo (SPKI) format which is what most email providers expect
    pub fn public_key_base64(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let der = self.public_key.to_public_key_der()?;
        Ok(BASE64.encode(der.as_bytes()))
    }

    /// Get the private key for signing
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    /// Get the public key
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Sign an email with DKIM
    /// 
    /// This adds a DKIM-Signature header to the email and returns the signed message.
    /// 
    /// # Arguments
    /// * `email` - The raw email data (headers + body)
    /// * `selector` - The DKIM selector (e.g., "default")  
    /// * `domain` - The signing domain (e.g., "example.com")
    /// 
    /// # Returns
    /// The email with DKIM-Signature header prepended
    pub fn sign(
        &self,
        email: &[u8],
        selector: &str,
        domain: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use sha2::{Sha256, Digest};
        
        let email_str = String::from_utf8_lossy(email);
        
        // Find the boundary between headers and body
        let (headers, body) = if let Some(pos) = email_str.find("\r\n\r\n") {
            (&email_str[..pos], &email_str[pos + 4..])
        } else if let Some(pos) = email_str.find("\n\n") {
            (&email_str[..pos], &email_str[pos + 2..])
        } else {
            // No body
            (email_str.as_ref(), "")
        };

        // Canonicalize body (simple canonicalization)
        // For simple: just ensure it ends with CRLF, empty body = CRLF
        let body_hash = {
            let mut hasher = Sha256::new();
            let canonicalized_body = if body.is_empty() {
                "".to_string()  // Empty body hashes to empty string
            } else {
                // Simple canonicalization: keep body as-is but ensure CRLF at end
                let mut b = body.replace('\n', "\r\n").replace("\r\r\n", "\r\n");
                if !b.ends_with("\r\n") {
                    b.push_str("\r\n");
                }
                b
            };
            hasher.update(canonicalized_body.as_bytes());
            BASE64.encode(hasher.finalize())
        };

        // Collect headers we want to sign
        let headers_to_sign = ["from", "to", "subject", "date", "message-id"];
        let mut signed_headers: Vec<&str> = Vec::new();
        
        for header_name in &headers_to_sign {
            // Check if header exists (case-insensitive)
            for line in headers.lines() {
                let lower = line.to_lowercase();
                if lower.starts_with(&format!("{}:", header_name)) {
                    signed_headers.push(header_name);
                    break;
                }
            }
        }

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Canonicalize headers for signing (relaxed canonicalization)
        // RFC 6376 Section 3.4.2:
        // - Convert header name to lowercase
        // - Unfold header (remove CRLF before WSP)
        // - Convert all sequences of WSP to a single SP
        // - Delete trailing WSP before CRLF
        let mut header_text = String::new();
        for header_name in &signed_headers {
            // Need to handle multi-line (folded) headers
            let mut found_header: Option<String> = None;
            let mut in_continuation = false;
            
            for line in headers.split("\r\n").chain(std::iter::once("")) {
                let line = if line.is_empty() { line } else { line.strip_suffix('\n').unwrap_or(line) };
                
                if in_continuation {
                    // Check if this is a continuation (starts with WSP)
                    if line.starts_with(' ') || line.starts_with('\t') {
                        if let Some(ref mut h) = found_header {
                            h.push(' ');
                            h.push_str(line.trim());
                        }
                        continue;
                    } else {
                        // End of this header
                        break;
                    }
                }
                
                let lower = line.to_lowercase();
                if lower.starts_with(&format!("{}:", header_name)) {
                    let colon_pos = line.find(':').unwrap();
                    let name = line[..colon_pos].to_lowercase();
                    let value = line[colon_pos + 1..].trim();
                    found_header = Some(format!("{}:{}", name, value));
                    in_continuation = true;
                }
            }
            
            if let Some(h) = found_header {
                // Collapse all whitespace to single spaces
                let canonicalized = h.split_whitespace().collect::<Vec<_>>().join(" ");
                // Re-split at colon to get proper format
                if let Some(colon_pos) = canonicalized.find(':') {
                    let name = &canonicalized[..colon_pos];
                    let value = canonicalized[colon_pos + 1..].trim();
                    header_text.push_str(&format!("{}:{}\r\n", name, value));
                }
            }
        }
        
        // Build the DKIM-Signature header template (for signing, without b= value)
        // Note: the dkim-signature header is also canonicalized for signing
        // Relaxed canonicalization: all WSP sequences become single SP, no trailing WSP
        let dkim_header_for_signing = format!(
            "dkim-signature:v=1; a=rsa-sha256; c=relaxed/simple; d={}; s={}; t={}; bh={}; h={}; b=",
            domain,
            selector,
            timestamp,
            body_hash,
            signed_headers.join(":")
        );
        
        // Add the DKIM-Signature header (without trailing CRLF for signing)
        header_text.push_str(&dkim_header_for_signing);

        // Sign the canonicalized headers directly (RSA-SHA256 does the hashing)
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature = signing_key.sign_with_rng(&mut rand::thread_rng(), header_text.as_bytes());
        let signature_b64 = BASE64.encode(signature.to_bytes());

        // Build the final DKIM-Signature header for the email
        let mut final_dkim_header = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d={}; s={};\r\n\tt={}; bh={};\r\n\th={};\r\n\tb=",
            domain,
            selector,
            timestamp,
            body_hash,
            signed_headers.join(":")
        );
        
        // Wrap signature at 76 chars
        for (i, chunk) in signature_b64.as_bytes().chunks(72).enumerate() {
            if i > 0 {
                final_dkim_header.push_str("\r\n\t ");
            }
            final_dkim_header.push_str(&String::from_utf8_lossy(chunk));
        }
        final_dkim_header.push_str("\r\n");

        // Prepend DKIM-Signature to the email
        let mut signed_email = final_dkim_header.into_bytes();
        signed_email.extend_from_slice(email);

        Ok(signed_email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_generate_and_save() {
        let dir = tempdir().unwrap();
        let keypair = DkimKeyPair::generate().unwrap();
        keypair.save(dir.path()).await.unwrap();

        assert!(dir.path().join("dkim_private.pem").exists());
        assert!(dir.path().join("dkim_public.pem").exists());
    }

    #[tokio::test]
    async fn test_load_or_generate() {
        let dir = tempdir().unwrap();

        // First call generates
        let keypair1 = DkimKeyPair::load_or_generate(dir.path()).await.unwrap();
        let pub1 = keypair1.public_key_base64().unwrap();

        // Second call loads
        let keypair2 = DkimKeyPair::load_or_generate(dir.path()).await.unwrap();
        let pub2 = keypair2.public_key_base64().unwrap();

        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_dkim_sign() {
        let keypair = DkimKeyPair::generate().unwrap();
        
        let email = b"From: sender@example.com\r\n\
                      To: recipient@example.org\r\n\
                      Subject: Test email\r\n\
                      Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n\
                      Message-ID: <test@example.com>\r\n\
                      \r\n\
                      Hello, this is a test email.\r\n";
        
        let signed = keypair.sign(email, "default", "example.com").unwrap();
        let signed_str = String::from_utf8_lossy(&signed);
        
        // Verify DKIM-Signature header is present
        assert!(signed_str.starts_with("DKIM-Signature:"));
        assert!(signed_str.contains("v=1"));
        assert!(signed_str.contains("a=rsa-sha256"));
        assert!(signed_str.contains("d=example.com"));
        assert!(signed_str.contains("s=default"));
        assert!(signed_str.contains("bh="));
        assert!(signed_str.contains("b="));
        
        // Verify original email content is preserved
        assert!(signed_str.contains("From: sender@example.com"));
        assert!(signed_str.contains("Hello, this is a test email."));
    }
}
