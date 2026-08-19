use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

use super::paths::{binary_path, log_dir};

pub fn install(cfg_path: &Path, _env_vars: HashMap<String, String>) -> Result<()> {
    let bin_path = binary_path()?;
    let log_dir = log_dir()?;

    info!("Configuration initialized on Windows:");
    info!("  Executable: {}", bin_path.display());
    info!("  Config:     {}", cfg_path.display());
    info!("  Logs:       {}", log_dir.display());
    info!("");
    info!("To run llm-proxy in the background or terminal:");
    info!("  llm-proxy.exe run");
    info!("");
    info!("To create a Windows Startup task, you can add 'llm-proxy.exe run' to your Startup folder or Task Scheduler.");
    Ok(())
}

pub fn start() -> Result<()> {
    let bin = binary_path()?;
    info!("Starting llm-proxy in background...");
    std::process::Command::new(bin).arg("run").spawn()?;
    info!("Service started. Check task manager or logs.");
    Ok(())
}

pub fn stop() -> Result<()> {
    info!("Stopping llm-proxy...");
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/IM", "llm-proxy.exe"])
        .output();
    info!("Service stopped.");
    Ok(())
}

pub fn restart() -> Result<()> {
    stop()?;
    std::thread::sleep(std::time::Duration::from_secs(1));
    start()?;
    Ok(())
}

pub fn status() -> Result<()> {
    let output = std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq llm-proxy.exe"])
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

pub fn logs() -> Result<()> {
    let log_dir = log_dir()?;
    let out_log = log_dir.join("stdout.log");
    let err_log = log_dir.join("stderr.log");

    println!("Log paths:");
    println!("  stdout: {}", out_log.display());
    println!("  stderr: {}", err_log.display());
    Ok(())
}

pub fn uninstall() -> Result<()> {
    stop()?;
    info!("Windows service uninstalled.");
    Ok(())
}
