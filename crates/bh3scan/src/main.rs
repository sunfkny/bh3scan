use log::info;

mod cli;
mod formatter;
mod logger;
mod sdk;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    info!("Done");
}
