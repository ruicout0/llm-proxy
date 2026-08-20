pub mod paths;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub mod fallback {
    use anyhow::Result;
    use std::collections::HashMap;
    use std::path::Path;
    use tracing::info;

    pub fn install(_cfg: &Path, _env: HashMap<String, String>) -> Result<()> {
        info!("Install complete. Use 'llm-proxy run' to start.");
        Ok(())
    }
    pub fn start() -> Result<()> {
        info!("Use 'llm-proxy run' to start.");
        Ok(())
    }
    pub fn stop() -> Result<()> {
        info!("Stop the running process via SIGINT/SIGTERM.");
        Ok(())
    }
    pub fn restart() -> Result<()> {
        info!("Restart by killing and re-running 'llm-proxy run'.");
        Ok(())
    }
    pub fn status() -> Result<()> {
        info!("Check active processes using ps.");
        Ok(())
    }
    pub fn logs() -> Result<()> {
        info!("Inspect logs in stdout or configured log directory.");
        Ok(())
    }
    pub fn uninstall() -> Result<()> {
        info!("Removed configuration.");
        Ok(())
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub use fallback::*;
