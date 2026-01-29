use rosetta_mail::client;
use rosetta_mail::client::config::hash_password;
use std::io::{self, Write};
use std::path::PathBuf;

fn print_usage() {
    eprintln!("Usage: client [OPTIONS] [STORAGE_PATH]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --hash-password    Generate an Argon2id password hash for config.toml");
    eprintln!("  --sample-config    Print a sample configuration file");
    eprintln!("  --help             Show this help message");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  STORAGE_PATH       Path to storage directory (default: current directory)");
    eprintln!();
    eprintln!("Environment:");
    eprintln!("  TUNNEL_STORAGE_PATH  Alternative way to set storage path");
}

fn hash_password_interactive() {
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    
    // Read password (note: this doesn't hide input, for that we'd need a crate like rpassword)
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim();
    
    if password.is_empty() {
        eprintln!("Error: Password cannot be empty");
        std::process::exit(1);
    }
    
    print!("Confirm password: ");
    io::stdout().flush().unwrap();
    
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    let confirm = confirm.trim();
    
    if password != confirm {
        eprintln!("Error: Passwords do not match");
        std::process::exit(1);
    }
    
    match hash_password(password) {
        Ok(hash) => {
            println!();
            println!("Add this to your config.toml under [accounts.users.\"your@email.com\"]:");
            println!("password_hash = \"{}\"", hash);
        }
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    
    let mut storage_path: Option<PathBuf> = None;
    
    // Check for CLI options
    for arg in &args[1..] {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--hash-password" => {
                hash_password_interactive();
                return Ok(());
            }
            "--sample-config" => {
                println!("{}", client::config::ClientConfig::sample());
                return Ok(());
            }
            s if s.starts_with('-') => {
                eprintln!("Unknown option: {}", s);
                print_usage();
                std::process::exit(1);
            }
            path => {
                // Non-option argument is the storage path
                if storage_path.is_none() {
                    storage_path = Some(PathBuf::from(path));
                } else {
                    eprintln!("Error: Multiple storage paths specified");
                    print_usage();
                    std::process::exit(1);
                }
            }
        }
    }
    
    // Install the ring crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    client::run_with_storage_path(storage_path).await
}
