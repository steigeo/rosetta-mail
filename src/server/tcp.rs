use crate::proto::{tunnel_message::Payload, CloseConnection, Data, NewConnection, TunnelMessage};
use crate::server::types::{ActiveClientId, ClientsMap, TcpConnection};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Global connection ID counter
static CONNECTION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Run a TCP listener on the specified port
pub async fn run_tcp_listener(
    port: u16,
    clients: ClientsMap,
    active_client_id: ActiveClientId,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("TCP listener started on port {}", port);

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New TCP connection from {} on port {}", addr, port);

        let clients = clients.clone();
        let active_client_id = active_client_id.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_tcp_connection(socket, addr, port, clients, active_client_id).await
            {
                eprintln!("Error handling TCP connection: {}", e);
            }
        });
    }
}

/// Handle a single TCP connection
async fn handle_tcp_connection(
    mut socket: TcpStream,
    addr: SocketAddr,
    port: u16,
    clients: ClientsMap,
    active_client_id: ActiveClientId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connection_id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

    // Get the active client
    let ws_client_id = {
        let active = active_client_id.read().await;
        match *active {
            Some(id) => id,
            None => {
                println!(
                    "No active websocket client, closing TCP connection {}",
                    connection_id
                );
                return Ok(());
            }
        }
    };

    // Create channel for sending data to this TCP connection
    let (tcp_tx, mut tcp_rx) = mpsc::channel::<Vec<u8>>(100);

    // Get the websocket client's sender and register this connection
    let ws_tx = {
        let mut clients_guard = clients.write().await;
        let client = match clients_guard.get_mut(&ws_client_id) {
            Some(c) => c,
            None => {
                println!(
                    "Active websocket client not found, closing TCP connection {}",
                    connection_id
                );
                return Ok(());
            }
        };

        client
            .connections
            .insert(connection_id, TcpConnection { tx: tcp_tx });

        client.tx.clone()
    };

    // Send NewConnection message to websocket client
    let new_conn_msg = TunnelMessage {
        payload: Some(Payload::NewConnection(NewConnection {
            connection_id,
            port: port as u32,
            remote_address: addr.to_string(),
        })),
    };

    if ws_tx.send(new_conn_msg).await.is_err() {
        println!("Failed to send new connection message, websocket client disconnected");
        return Ok(());
    }

    let (mut read_half, mut write_half) = socket.split();

    // Task to read from TCP and send to websocket
    let ws_tx_clone = ws_tx.clone();
    let read_task = async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => {
                    // Connection closed
                    let close_msg = TunnelMessage {
                        payload: Some(Payload::CloseConnection(CloseConnection { connection_id })),
                    };
                    let _ = ws_tx_clone.send(close_msg).await;
                    break;
                }
                Ok(n) => {
                    let data_msg = TunnelMessage {
                        payload: Some(Payload::Data(Data {
                            connection_id,
                            payload: buf[..n].to_vec(),
                        })),
                    };
                    if ws_tx_clone.send(data_msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from TCP connection {}: {}", connection_id, e);
                    let close_msg = TunnelMessage {
                        payload: Some(Payload::CloseConnection(CloseConnection { connection_id })),
                    };
                    let _ = ws_tx_clone.send(close_msg).await;
                    break;
                }
            }
        }
    };

    // Task to receive from websocket (via channel) and write to TCP
    let write_task = async move {
        while let Some(data) = tcp_rx.recv().await {
            if write_half.write_all(&data).await.is_err() {
                break;
            }
        }
    };

    // Run both tasks
    tokio::select! {
        _ = read_task => {},
        _ = write_task => {},
    }

    // Clean up connection from client's map
    {
        let mut clients_guard = clients.write().await;
        if let Some(client) = clients_guard.get_mut(&ws_client_id) {
            client.connections.remove(&connection_id);
        }
    }

    println!("TCP connection {} closed", connection_id);
    Ok(())
}
