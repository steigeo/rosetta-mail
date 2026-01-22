use rosetta_mail::server::{
    run_tcp_listener, run_websocket_server, ActiveClientId, ClientsMap, TCP_PORTS,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let clients: ClientsMap = Arc::new(RwLock::new(HashMap::new()));
    let active_client_id: ActiveClientId = Arc::new(RwLock::new(None));

    // Spawn TCP listeners for each port
    for &port in TCP_PORTS {
        let clients = clients.clone();
        let active_client_id = active_client_id.clone();
        tokio::spawn(async move {
            if let Err(e) = run_tcp_listener(port, clients, active_client_id).await {
                eprintln!("TCP listener on port {} failed: {}", port, e);
            }
        });
    }

    // Run websocket server
    run_websocket_server(clients, active_client_id).await?;

    Ok(())
}
