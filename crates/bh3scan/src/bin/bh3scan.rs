use log::info;
use std::error::Error;

pub fn print_error(err: &dyn Error) {
    eprintln!("Error: {}", err);

    let mut current = err;
    while let Some(source) = current.source() {
        eprintln!("  Caused by: {}", source);
        current = source;
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = bh3scan::run().await {
        print_error(&e);
        std::process::exit(1);
    }
    info!("Done");
}
