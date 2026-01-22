use crate::client::dns::{CloudflareClient, DnsRecord, DnsRecordType};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
const ACME_CONTENT_TYPE: &str = "application/jose+json";

/// ACME client for Let's Encrypt certificate issuance
pub struct AcmeClient {
    client: Client,
    directory: AcmeDirectory,
    account_key: KeyPair,
    account_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Debug, Serialize)]
struct JwsProtected {
    alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    nonce: String,
    url: String,
}

#[derive(Debug, Serialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Serialize)]
struct NewAccountPayload {
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
}

#[derive(Debug, Serialize)]
struct NewOrderPayload {
    identifiers: Vec<Identifier>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    id_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct OrderResponse {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationResponse {
    #[allow(dead_code)]
    status: String,
    identifier: Identifier,
    challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    challenge_type: String,
    url: String,
    token: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct FinalizePayload {
    csr: String,
}

impl AcmeClient {
    /// Create a new ACME client
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = Client::new();

        // Fetch directory
        let directory: AcmeDirectory = client
            .get(LETS_ENCRYPT_DIRECTORY)
            .send()
            .await?
            .json()
            .await?;

        // Generate account key (ECDSA P-256)
        let account_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        Ok(Self {
            client,
            directory,
            account_key,
            account_url: None,
        })
    }

    /// Register a new account or get existing account URL
    pub async fn register_account(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let nonce = self.get_nonce().await?;

        let payload = NewAccountPayload {
            terms_of_service_agreed: true,
        };

        let (_response, headers): (serde_json::Value, _) = self
            .signed_request(&self.directory.new_account.clone(), &payload, &nonce, true)
            .await?;

        // Get account URL from Location header
        if let Some(location) = headers.get("location") {
            self.account_url = Some(location.to_str()?.to_string());
        }

        Ok(())
    }

    /// Request a certificate for a domain using DNS-01 challenge
    pub async fn request_certificate(
        &mut self,
        domain: &str,
        dns_client: &CloudflareClient,
    ) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        if self.account_url.is_none() {
            self.register_account().await?;
        }

        // Create order
        let nonce = self.get_nonce().await?;
        let order_payload = NewOrderPayload {
            identifiers: vec![Identifier {
                id_type: "dns".to_string(),
                value: domain.to_string(),
            }],
        };

        let (order_response, headers): (OrderResponse, _) = self
            .signed_request(&self.directory.new_order.clone(), &order_payload, &nonce, false)
            .await?;

        let order_url = headers
            .get("location")
            .ok_or("No order URL")?
            .to_str()?
            .to_string();

        // Process authorizations
        for auth_url in &order_response.authorizations {
            self.process_authorization(auth_url, dns_client).await?;
        }

        // Wait for order to be ready
        let order = self.wait_for_order_ready(&order_url).await?;

        // Generate certificate key and CSR
        let cert_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let csr = self.generate_csr(domain, &cert_key)?;

        // Finalize order
        let nonce = self.get_nonce().await?;
        let finalize_payload = FinalizePayload {
            csr: BASE64URL.encode(csr),
        };

        let _: serde_json::Value = self
            .signed_request(&order.finalize, &finalize_payload, &nonce, false)
            .await?
            .0;

        // Wait for certificate
        let final_order = self.wait_for_certificate(&order_url).await?;

        // Download certificate
        let cert_url = final_order.certificate.ok_or("No certificate URL")?;
        let nonce = self.get_nonce().await?;
        let cert_pem = self.download_certificate(&cert_url, &nonce).await?;

        // Return certificate and private key
        let key_pem = cert_key.serialize_pem();

        Ok((cert_pem, key_pem))
    }

    async fn process_authorization(
        &self,
        auth_url: &str,
        dns_client: &CloudflareClient,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let nonce = self.get_nonce().await?;
        let (auth, _): (AuthorizationResponse, _) =
            self.signed_request_get(auth_url, &nonce).await?;

        // Find DNS-01 challenge
        let dns_challenge = auth
            .challenges
            .iter()
            .find(|c| c.challenge_type == "dns-01")
            .ok_or("No DNS-01 challenge found")?;

        if dns_challenge.status == "valid" {
            return Ok(());
        }

        // Create key authorization
        let key_authz = self.key_authorization(&dns_challenge.token)?;

        // DNS TXT record value is base64url(sha256(key_authorization))
        let mut hasher = Sha256::new();
        hasher.update(key_authz.as_bytes());
        let digest = hasher.finalize();
        let txt_value = BASE64URL.encode(digest);

        // Set DNS record
        let challenge_domain = format!("_acme-challenge.{}", auth.identifier.value);
        let record = DnsRecord::txt(&challenge_domain, &txt_value, 60);
        dns_client.upsert_record(&record).await?;

        println!("Set DNS challenge for {}: {}", challenge_domain, txt_value);

        // Wait for DNS propagation
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Respond to challenge
        let nonce = self.get_nonce().await?;
        let empty_payload = serde_json::json!({});
        let _: serde_json::Value = self
            .signed_request(&dns_challenge.url, &empty_payload, &nonce, false)
            .await?
            .0;

        // Wait for challenge to be validated
        self.wait_for_challenge_valid(&dns_challenge.url).await?;

        // Clean up DNS record
        if let Ok(Some(record_id)) = dns_client
            .find_record(&challenge_domain, &DnsRecordType::TXT)
            .await
        {
            let _ = dns_client.delete_record(&record_id).await;
        }

        Ok(())
    }

    async fn wait_for_challenge_valid(
        &self,
        challenge_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for _ in 0..30 {
            let nonce = self.get_nonce().await?;
            let (challenge, _): (Challenge, _) =
                self.signed_request_get(challenge_url, &nonce).await?;

            match challenge.status.as_str() {
                "valid" => return Ok(()),
                "invalid" => return Err("Challenge failed".into()),
                _ => tokio::time::sleep(Duration::from_secs(2)).await,
            }
        }
        Err("Challenge timeout".into())
    }

    async fn wait_for_order_ready(
        &self,
        order_url: &str,
    ) -> Result<OrderResponse, Box<dyn std::error::Error + Send + Sync>> {
        for _ in 0..30 {
            let nonce = self.get_nonce().await?;
            let (order, _): (OrderResponse, _) =
                self.signed_request_get(order_url, &nonce).await?;

            match order.status.as_str() {
                "ready" | "valid" => return Ok(order),
                "invalid" => return Err("Order failed".into()),
                _ => tokio::time::sleep(Duration::from_secs(2)).await,
            }
        }
        Err("Order timeout".into())
    }

    async fn wait_for_certificate(
        &self,
        order_url: &str,
    ) -> Result<OrderResponse, Box<dyn std::error::Error + Send + Sync>> {
        for _ in 0..30 {
            let nonce = self.get_nonce().await?;
            let (order, _): (OrderResponse, _) =
                self.signed_request_get(order_url, &nonce).await?;

            if order.status == "valid" && order.certificate.is_some() {
                return Ok(order);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err("Certificate timeout".into())
    }

    async fn download_certificate(
        &self,
        cert_url: &str,
        nonce: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let response = self
            .client
            .post(cert_url)
            .header("Content-Type", ACME_CONTENT_TYPE)
            .body(self.create_jws_body("", cert_url, nonce, false)?)
            .send()
            .await?;

        Ok(response.text().await?)
    }

    fn generate_csr(
        &self,
        domain: &str,
        key: &KeyPair,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);
        params.subject_alt_names = vec![rcgen::SanType::DnsName(domain.try_into()?)];

        let csr = params.serialize_request(key)?;
        Ok(csr.der().to_vec())
    }

    async fn get_nonce(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let response = self.client.head(&self.directory.new_nonce).send().await?;
        let nonce = response
            .headers()
            .get("replay-nonce")
            .ok_or("No nonce")?
            .to_str()?
            .to_string();
        Ok(nonce)
    }

    fn key_authorization(
        &self,
        token: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let jwk_thumbprint = self.jwk_thumbprint()?;
        Ok(format!("{}.{}", token, jwk_thumbprint))
    }

    fn jwk_thumbprint(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let jwk = self.get_jwk()?;
        let jwk_json = serde_json::json!({
            "crv": jwk.crv,
            "kty": jwk.kty,
            "x": jwk.x,
            "y": jwk.y,
        });
        let canonical = serde_json::to_string(&jwk_json)?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();
        Ok(BASE64URL.encode(digest))
    }

    fn get_jwk(&self) -> Result<Jwk, Box<dyn std::error::Error + Send + Sync>> {
        let public_key_der = self.account_key.public_key_der();
        // Parse EC public key - skip the header to get x and y coordinates
        // For P-256, the format is: 04 || x (32 bytes) || y (32 bytes)
        let raw_key = &public_key_der[public_key_der.len() - 65..];
        if raw_key[0] != 0x04 {
            return Err("Invalid EC public key format".into());
        }
        let x = BASE64URL.encode(&raw_key[1..33]);
        let y = BASE64URL.encode(&raw_key[33..65]);

        Ok(Jwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
        })
    }

    async fn signed_request<T: for<'de> Deserialize<'de>, P: Serialize>(
        &self,
        url: &str,
        payload: &P,
        nonce: &str,
        use_jwk: bool,
    ) -> Result<(T, reqwest::header::HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
        let payload_json = serde_json::to_string(payload)?;
        let body = self.create_jws_body(&payload_json, url, nonce, use_jwk)?;

        let response = self
            .client
            .post(url)
            .header("Content-Type", ACME_CONTENT_TYPE)
            .body(body)
            .send()
            .await?;

        let headers = response.headers().clone();
        let result: T = response.json().await?;
        Ok((result, headers))
    }

    async fn signed_request_get<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        nonce: &str,
    ) -> Result<(T, reqwest::header::HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
        let body = self.create_jws_body("", url, nonce, false)?;

        let response = self
            .client
            .post(url)
            .header("Content-Type", ACME_CONTENT_TYPE)
            .body(body)
            .send()
            .await?;

        let headers = response.headers().clone();
        let result: T = response.json().await?;
        Ok((result, headers))
    }

    fn create_jws_body(
        &self,
        payload: &str,
        url: &str,
        nonce: &str,
        use_jwk: bool,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let protected = JwsProtected {
            alg: "ES256".to_string(),
            jwk: if use_jwk { Some(self.get_jwk()?) } else { None },
            kid: if !use_jwk {
                self.account_url.clone()
            } else {
                None
            },
            nonce: nonce.to_string(),
            url: url.to_string(),
        };

        let protected_b64 = BASE64URL.encode(serde_json::to_string(&protected)?);
        let payload_b64 = if payload.is_empty() {
            String::new()
        } else {
            BASE64URL.encode(payload)
        };

        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let signature = self.sign(signing_input.as_bytes())?;
        let signature_b64 = BASE64URL.encode(signature);

        let jws = serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        });

        Ok(serde_json::to_string(&jws)?)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        
        // This is a simplified signing - in production, use the rcgen key directly
        // For now, we'll use a workaround
        let key_der = self.account_key.serialize_der();
        let rng = ring::rand::SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key_der, &rng)
            .map_err(|e| format!("Failed to create key pair: {:?}", e))?;
        let sig = key_pair.sign(&rng, data)
            .map_err(|e| format!("Failed to sign: {:?}", e))?;
        Ok(sig.as_ref().to_vec())
    }
}
