use crate::proto::{tunnel_message::Payload, CloseConnection, Data, OutboundConnectResponse, TunnelMessage};
use crate::server::config::{get_auth_key, WEBSOCKET_PORT};
use crate::server::types::{ActiveClientId, ClientsMap, TcpConnection, WsClient};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Global websocket client ID counter
static WS_CLIENT_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Run the WebSocket server
pub async fn run_websocket_server(
    clients: ClientsMap,
    active_client_id: ActiveClientId,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", WEBSOCKET_PORT)).await?;
    println!("WebSocket server started on port {}", WEBSOCKET_PORT);

    let expected_auth_key = get_auth_key();
    if expected_auth_key.is_some() {
        println!("Authentication enabled");
    } else {
        println!("Warning: No TUNNEL_AUTH_KEY set, authentication disabled");
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New WebSocket connection from {}", addr);

        let clients = clients.clone();
        let active_client_id = active_client_id.clone();
        let expected_auth_key = expected_auth_key.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_websocket_connection(stream, clients, active_client_id, expected_auth_key)
                    .await
            {
                eprintln!("Error handling WebSocket connection: {}", e);
            }
        });
    }
}

/// Handle a single WebSocket connection
async fn handle_websocket_connection(
    stream: TcpStream,
    clients: ClientsMap,
    active_client_id: ActiveClientId,
    expected_auth_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Accept websocket with authentication callback
    let ws_stream =
        tokio_tungstenite::accept_hdr_async(stream, |request: &Request, response: Response| {
            // Check authentication if key is configured
            if let Some(ref expected_key) = expected_auth_key {
                let provided_key = request
                    .headers()
                    .get("X-Auth-Key")
                    .and_then(|v| v.to_str().ok());

                match provided_key {
                    Some(key) if key == expected_key => {
                        println!("Client authenticated successfully");
                        Ok(response)
                    }
                    Some(_) => {
                        println!("Client authentication failed: invalid key");
                        Err(Response::builder()
                            .status(401)
                            .body(Some("Unauthorized: Invalid authentication key".into()))
                            .unwrap())
                    }
                    None => {
                        println!("Client authentication failed: no key provided");
                        Err(Response::builder()
                            .status(401)
                            .body(Some("Unauthorized: Authentication key required".into()))
                            .unwrap())
                    }
                }
            } else {
                // No auth configured, accept all connections
                Ok(response)
            }
        })
        .await?;

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    let client_id = WS_CLIENT_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    println!("WebSocket client {} connected", client_id);

    // Create channel for sending messages to this websocket
    let (tx, mut rx) = mpsc::channel::<TunnelMessage>(100);

    // Register client and set as active
    {
        let mut clients_guard = clients.write().await;
        clients_guard.insert(
            client_id,
            WsClient {
                tx,
                connections: HashMap::new(),
            },
        );
    }
    {
        let mut active = active_client_id.write().await;
        *active = Some(client_id);
    }

    println!("WebSocket client {} is now the active client", client_id);

    // Task to send messages to websocket
    let send_task = async {
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

    // Task to receive messages from websocket
    let clients_clone = clients.clone();
    let recv_task = async {
        while let Some(msg_result) = ws_source.next().await {
            match msg_result {
                Ok(WsMessage::Binary(data)) => {
                    if let Ok(tunnel_msg) = TunnelMessage::decode(data.as_ref()) {
                        handle_client_message(client_id, tunnel_msg, &clients_clone).await;
                    }
                }
                Ok(WsMessage::Close(_)) => break,
                Err(e) => {
                    eprintln!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    };

    // Run both tasks
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    // Clean up: close all TCP connections for this client
    {
        let mut clients_guard = clients.write().await;
        if let Some(client) = clients_guard.remove(&client_id) {
            println!(
                "Closing {} TCP connections for websocket client {}",
                client.connections.len(),
                client_id
            );
            // Dropping the client will drop all TcpConnection entries,
            // which drops the senders, causing the TCP write tasks to end
        }
    }

    // If this was the active client, clear it or set to another client
    {
        let mut active = active_client_id.write().await;
        if *active == Some(client_id) {
            let clients_guard = clients.read().await;
            // Set to any remaining client, or None
            *active = clients_guard.keys().next().copied();
            if let Some(new_active) = *active {
                println!("WebSocket client {} is now the active client", new_active);
            } else {
                println!("No active websocket clients remaining");
            }
        }
    }

    println!("WebSocket client {} disconnected", client_id);
    Ok(())
}

/// Handle a message received from a websocket client
async fn handle_client_message(client_id: u64, msg: TunnelMessage, clients: &ClientsMap) {
    match msg.payload {
        Some(Payload::Data(data)) => {
            let clients_guard = clients.read().await;
            if let Some(client) = clients_guard.get(&client_id) {
                if let Some(conn) = client.connections.get(&data.connection_id) {
                    let _ = conn.tx.send(data.payload).await;
                }
            }
        }
        Some(Payload::CloseConnection(close)) => {
            let mut clients_guard = clients.write().await;
            if let Some(client) = clients_guard.get_mut(&client_id) {
                if let Some(_conn) = client.connections.remove(&close.connection_id) {
                    println!(
                        "Client requested close of connection {}",
                        close.connection_id
                    );
                    // Dropping the connection will close the channel and end the write task
                }
            }
        }
        Some(Payload::OutboundConnectRequest(req)) => {
            // Client wants to open an outbound connection
            println!(
                "Outbound connection request: {}:{} (conn_id={})",
                req.host, req.port, req.connection_id
            );
            
            let clients_clone = clients.clone();
            tokio::spawn(async move {
                handle_outbound_connect(client_id, req.connection_id, &req.host, req.port as u16, &clients_clone).await;
            });
        }
        _ => {}
    }
}

/// Handle an outbound connection request from client
async fn handle_outbound_connect(
    client_id: u64,
    connection_id: u64,
    host: &str,
    port: u16,
    clients: &ClientsMap,
) {
    // Try to connect to the target
    let addr = format!("{}:{}", host, port);
    let connect_result = TcpStream::connect(&addr).await;

    match connect_result {
        Ok(stream) => {
            let remote_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            println!(
                "Outbound connection {} established to {}",
                connection_id, remote_addr
            );

            // Send success response
            let response = TunnelMessage {
                payload: Some(Payload::OutboundConnectResponse(OutboundConnectResponse {
                    connection_id,
                    success: true,
                    error: String::new(),
                    remote_address: remote_addr.clone(),
                })),
            };

            // Set up bidirectional forwarding (same as inbound connections)
            let (mut read_half, mut write_half) = stream.into_split();
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

            // Register the connection
            {
                let mut clients_guard = clients.write().await;
                if let Some(client) = clients_guard.get_mut(&client_id) {
                    client.connections.insert(
                        connection_id,
                        TcpConnection { tx },
                    );
                    let _ = client.tx.send(response).await;
                }
            }

            let clients_read = clients.clone();

            // Task to read from TCP and send to WebSocket
            let read_task = async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => break, // Connection closed
                        Ok(n) => {
                            let data_msg = TunnelMessage {
                                payload: Some(Payload::Data(Data {
                                    connection_id,
                                    payload: buf[..n].to_vec(),
                                })),
                            };
                            let clients_guard = clients_read.read().await;
                            if let Some(client) = clients_guard.get(&client_id) {
                                if client.tx.send(data_msg).await.is_err() {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }

                // Connection closed, notify client
                let close_msg = TunnelMessage {
                    payload: Some(Payload::CloseConnection(CloseConnection { connection_id })),
                };
                let clients_guard = clients_read.read().await;
                if let Some(client) = clients_guard.get(&client_id) {
                    let _ = client.tx.send(close_msg).await;
                }
            };

            // Task to write data from channel to TCP
            let write_task = async move {
                while let Some(data) = rx.recv().await {
                    if write_half.write_all(&data).await.is_err() {
                        break;
                    }
                }
            };

            tokio::spawn(async move {
                tokio::select! {
                    _ = read_task => {},
                    _ = write_task => {},
                }
            });
        }
        Err(e) => {
            println!(
                "Outbound connection {} to {} failed: {}",
                connection_id, addr, e
            );

            // Send failure response
            let response = TunnelMessage {
                payload: Some(Payload::OutboundConnectResponse(OutboundConnectResponse {
                    connection_id,
                    success: false,
                    error: e.to_string(),
                    remote_address: String::new(),
                })),
            };

            let clients_guard = clients.read().await;
            if let Some(client) = clients_guard.get(&client_id) {
                let _ = client.tx.send(response).await;
            }
        }
    }
}
