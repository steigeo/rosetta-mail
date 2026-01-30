use crate::client::connections::SharedConnectionManager;
use crate::client::smtp::OutboundSender;
use crate::proto::{tunnel_message::Payload, CloseConnection, Data, TunnelMessage};
use crate::{verbose, log_error};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Shared outbound sender type
pub type SharedOutboundSender = Arc<RwLock<OutboundSender>>;

/// Handle a message received from the server
pub async fn handle_server_message(
    msg: TunnelMessage,
    tx: &mpsc::Sender<TunnelMessage>,
    conn_manager: &SharedConnectionManager,
    outbound_sender: &SharedOutboundSender,
) {
    match msg.payload {
        Some(Payload::NewConnection(new_conn)) => {
            handle_new_connection(
                new_conn.connection_id,
                new_conn.port,
                &new_conn.remote_address,
                tx,
                conn_manager,
            )
            .await;
        }
        Some(Payload::Data(data)) => {
            handle_data(data.connection_id, &data.payload, tx, conn_manager, outbound_sender).await;
        }
        Some(Payload::CloseConnection(close)) => {
            handle_close(close.connection_id, conn_manager).await;
        }
        Some(Payload::OutboundConnectResponse(resp)) => {
            // Handle response to our outbound connection request
            handle_outbound_connect_response(
                resp.connection_id,
                resp.success,
                &resp.error,
                &resp.remote_address,
                conn_manager,
                outbound_sender,
            )
            .await;
        }
        Some(Payload::OutboundConnectRequest(_)) => {
            // Server should not send connect requests to client
            log_error!("Unexpected OutboundConnectRequest from server");
        }
        None => {}
    }
}

/// Handle outbound connection response from server
async fn handle_outbound_connect_response(
    connection_id: u64,
    success: bool,
    error: &str,
    remote_address: &str,
    conn_manager: &SharedConnectionManager,
    outbound_sender: &SharedOutboundSender,
) {
    if success {
        verbose!(
            "Outbound connection {} established to {}",
            connection_id, remote_address
        );
    } else {
        verbose!(
            "Outbound connection {} failed: {}",
            connection_id, error
        );
    }
    
    // Check if this is for our outbound sender (high connection IDs)
    let sender = outbound_sender.read().await;
    if sender.is_outbound_connection(connection_id) {
        // This is a response for the outbound sender
        verbose!("Routing connect response to outbound sender for connection {}", connection_id);
        sender.handle_connect_response(connection_id, success, error).await;
    } else {
        // This is for the connection manager
        let mut manager = conn_manager.write().await;
        manager.handle_outbound_connect_response(connection_id, success, error).await;
    }
}

/// Handle a new connection notification from server
async fn handle_new_connection(
    connection_id: u64,
    port: u32,
    remote_address: &str,
    tx: &mpsc::Sender<TunnelMessage>,
    conn_manager: &SharedConnectionManager,
) {
    verbose!(
        "New connection: id={}, port={}, remote={}",
        connection_id, port, remote_address
    );

    // Register connection and get initial response (e.g., SMTP greeting, TLS handshake)
    let (initial_response, should_close) = {
        let mut manager = conn_manager.write().await;
        manager.add_connection(connection_id, port, remote_address.to_string())
    };

    // Send initial response if any
    if let Some(response_data) = initial_response {
        let response = TunnelMessage {
            payload: Some(Payload::Data(Data {
                connection_id,
                payload: response_data,
            })),
        };
        if tx.send(response).await.is_err() {
            log_error!(
                "Failed to send initial response for connection {}",
                connection_id
            );
        }
    }

    // Close connection if needed (e.g., TLS setup failed)
    if should_close {
        let close_msg = TunnelMessage {
            payload: Some(Payload::CloseConnection(CloseConnection { connection_id })),
        };
        if tx.send(close_msg).await.is_err() {
            log_error!(
                "Failed to send close message for connection {}",
                connection_id
            );
        }

        let mut manager = conn_manager.write().await;
        manager.remove_connection(connection_id);
        verbose!("Closed connection {} (setup failed)", connection_id);
    }
}

/// Handle data received from server
async fn handle_data(
    connection_id: u64,
    payload: &[u8],
    tx: &mpsc::Sender<TunnelMessage>,
    conn_manager: &SharedConnectionManager,
    outbound_sender: &SharedOutboundSender,
) {
    // Check if this is data for an outbound connection (email sending)
    {
        let sender = outbound_sender.read().await;
        if sender.is_outbound_connection(connection_id) {
            // This data is for an outbound SMTP connection we initiated
            verbose!("Routing {} bytes to outbound sender for connection {}", payload.len(), connection_id);
            sender.handle_data(connection_id, payload).await;
            return;
        }
    }

    // Only print human-readable text (ASCII), skip binary/TLS data
    if payload.iter().all(|&b| b.is_ascii() && (b >= 32 || b == b'\r' || b == b'\n' || b == b'\t')) {
        let text = String::from_utf8_lossy(payload);
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            verbose!("Data received on connection {}: {}", connection_id, trimmed);
        }
    } else {
        verbose!(
            "Data received on connection {}: [{} bytes of binary data]",
            connection_id,
            payload.len()
        );
    }

    // Process data through the connection manager
    let (response_data, should_close, needs_tls_upgrade) = {
        let mut manager = conn_manager.write().await;
        let result = manager.process_data(connection_id, payload);
        let needs_upgrade = manager.needs_tls_upgrade(connection_id);
        (result.0, result.1, needs_upgrade)
    };

    // Send response if any
    if let Some(data) = response_data {
        let response = TunnelMessage {
            payload: Some(Payload::Data(Data {
                connection_id,
                payload: data,
            })),
        };
        if tx.send(response).await.is_err() {
            log_error!("Failed to send response for connection {}", connection_id);
            return;
        }
    }

    // Handle STARTTLS upgrade if needed
    if needs_tls_upgrade {
        verbose!("Upgrading connection {} to TLS (STARTTLS)", connection_id);
        let mut manager = conn_manager.write().await;
        // Upgrade to TLS - the connection is now ready for TLS handshake
        // The next data packet will be a TLS ClientHello
        if !manager.upgrade_smtp_to_tls(connection_id) {
            log_error!("Failed to upgrade connection {} to TLS", connection_id);
        }
    }

    // Close connection if needed
    if should_close {
        let close_msg = TunnelMessage {
            payload: Some(Payload::CloseConnection(CloseConnection { connection_id })),
        };
        if tx.send(close_msg).await.is_err() {
            log_error!(
                "Failed to send close message for connection {}",
                connection_id
            );
        }

        // Remove from manager
        let mut manager = conn_manager.write().await;
        manager.remove_connection(connection_id);

        verbose!("Closed connection {}", connection_id);
    }
}

/// Handle a connection close notification from server
async fn handle_close(connection_id: u64, conn_manager: &SharedConnectionManager) {
    verbose!("Connection {} closed by server", connection_id);

    let mut manager = conn_manager.write().await;
    manager.remove_connection(connection_id);
}
