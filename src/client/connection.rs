use crate::client::config::{get_auth_key, get_config, get_server_url, get_storage_path, init_config, set_storage_path};
use crate::client::connections::ConnectionManager;
use crate::client::handler::handle_server_message;
use crate::client::init::initialize;
use crate::client::smtp::{MailTransaction, OutboundSender};
use crate::client::storage::EmailStorage;
use crate::proto::TunnelMessage;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Connect to the server and run the main client loop
pub async fn run_with_storage_path(storage_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set storage path override if provided
    if let Some(path) = storage_path {
        set_storage_path(path);
    }
    
    // Load configuration from config.toml (with env var overrides)
    let _config = init_config().await?;
    println!("Configuration loaded from {:?}", get_storage_path().join("config.toml"));
    
    // Initialize email infrastructure (DKIM, certificates, DNS)
    let email_config = initialize().await?;
    
    let server_url = get_server_url();
    println!("\nConnecting to server at {}...", server_url);

    // Build request with auth header if key is set
    let mut request = server_url.into_client_request()?;
    if let Some(auth_key) = get_auth_key() {
        request.headers_mut().insert(
            "X-Auth-Key",
            auth_key.parse().map_err(|_| "Invalid auth key")?,
        );
        println!("Using authentication key");
    } else {
        println!("Warning: No TUNNEL_AUTH_KEY set, connecting without authentication");
    }

    let (ws_stream, _) = tokio_tungstenite::connect_async(request).await?;
    println!("Connected to server!");

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // Get accounts config
    let accounts = get_config().accounts.clone();

    // Create email storage
    let storage_path = get_storage_path();
    let email_storage = Arc::new(EmailStorage::new(&storage_path));

    // Create connection manager with TLS config
    let (hostname, mail_domain, tls_available, certificate, mta_sts_certificate) = if let Some(ref init_result) = email_config {
        let config = init_result.config.read().await;
        (
            config.hostname.clone(),
            config.mail_domain.clone(),
            config.tls_available,
            config.certificate.clone(),
            config.mta_sts_certificate.clone(),
        )
    } else {
        (String::new(), String::new(), false, None, None)
    };
    
    let mut conn_manager = ConnectionManager::new_with_tls(
        hostname.clone(),
        mail_domain.clone(),
        tls_available,
        certificate,
        mta_sts_certificate,
        accounts,
        email_storage.clone(),
    );

    // Channel for outbound email requests
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<MailTransaction>(100);

    // Set up email storage callback
    let storage_clone = email_storage.clone();
    let outbound_tx_clone = outbound_tx.clone();
    
    conn_manager.on_email_received = Some(Box::new(move |transaction| {
        let storage = storage_clone.clone();
        let outbound_tx = outbound_tx_clone.clone();
        
        if transaction.is_outbound {
            // Outbound email from submission port - send to outbound task
            println!(
                "OUTBOUND email: FROM={} TO={:?} SIZE={} user={:?}",
                transaction.mail_from,
                transaction.rcpt_to,
                transaction.data.len(),
                transaction.authenticated_user
            );
            
            // Clone for the send task
            let transaction_clone = transaction.clone();
            
            // Send to outbound processing task
            tokio::spawn(async move {
                if let Err(e) = outbound_tx.send(transaction_clone).await {
                    eprintln!("Failed to queue outbound email: {}", e);
                }
            });
            
            // TODO: Store a copy in the user's Sent folder
        } else {
            // Inbound email - store it
            println!(
                "INBOUND email: FROM={} TO={:?} SIZE={}",
                transaction.mail_from,
                transaction.rcpt_to,
                transaction.data.len()
            );
            
            // Spawn a task to store the email asynchronously
            tokio::spawn(async move {
                if let Err(e) = storage.store_email(&transaction).await {
                    eprintln!("Failed to store email: {}", e);
                }
            });
        }
    }));

    let conn_manager = Arc::new(RwLock::new(conn_manager));

    // Channel for sending messages back to server
    let (tx, mut rx) = mpsc::channel::<TunnelMessage>(100);
    
    // Clone tx for the outbound task
    let outbound_tunnel_tx = tx.clone();

    // Get DKIM keypair for outbound signing
    let dkim_keypair = if let Some(ref init_result) = email_config {
        let config = init_result.config.read().await;
        config.dkim_keypair.clone()
    } else {
        None
    };

    // Create outbound sender
    let outbound_sender = match OutboundSender::new(
        dkim_keypair,
        mail_domain.clone(),
        hostname.clone(),
        outbound_tunnel_tx,
    ) {
        Ok(sender) => Arc::new(RwLock::new(sender)),
        Err(e) => {
            eprintln!("Warning: Failed to create outbound sender: {}", e);
            eprintln!("Outbound email will not work!");
            return Err(e.into());
        }
    };

    // Task to process outbound emails
    let outbound_sender_task = outbound_sender.clone();
    let outbound_task = async move {
        while let Some(transaction) = outbound_rx.recv().await {
            println!("Processing outbound email to: {:?}", transaction.rcpt_to);
            let sender = outbound_sender_task.read().await;
            if let Err(e) = sender.send(&transaction).await {
                eprintln!("Failed to send outbound email: {}", e);
            }
        }
    };

    // Task to send messages to server
    let send_task = async move {
        while let Some(msg) = rx.recv().await {
            let encoded = msg.encode_to_vec();
            if ws_sink
                .send(WsMessage::Binary(encoded.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    };

    // Task to receive messages from server
    let conn_manager_recv = conn_manager.clone();
    let outbound_sender_recv = outbound_sender.clone();
    let recv_task = async move {
        while let Some(msg_result) = ws_source.next().await {
            match msg_result {
                Ok(WsMessage::Binary(data)) => {
                    if let Ok(tunnel_msg) = TunnelMessage::decode(data.as_ref()) {
                        handle_server_message(tunnel_msg, &tx, &conn_manager_recv, &outbound_sender_recv).await;
                    }
                }
                Ok(WsMessage::Close(_)) => {
                    println!("Server closed connection");
                    break;
                }
                Err(e) => {
                    eprintln!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    };

    // Run all tasks
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
        _ = outbound_task => {},
    }

    println!("Disconnected from server");
    Ok(())
}

/// Connect to the server and run the main client loop (convenience wrapper)
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_storage_path(None).await
}
