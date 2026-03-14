//! Zentinel Gateway API Controller binary.
//!
//! Runs as a standalone Kubernetes controller that watches Gateway API
//! resources and translates them into Zentinel proxy configuration.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use zentinel_gateway::GatewayController;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("zentinel_gateway=info,kube=warn")),
        )
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting Zentinel Gateway API controller"
    );

    let controller = GatewayController::new().await?;

    // Install signal handler for graceful shutdown
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        result = controller.run() => {
            if let Err(e) = result {
                error!(error = %e, "Controller exited with error");
                std::process::exit(1);
            }
        }
        _ = ctrl_c => {
            info!("Received shutdown signal, exiting");
        }
    }

    Ok(())
}
