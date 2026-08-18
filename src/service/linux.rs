use anyhow::{Context, Result};
use dirs::home_dir;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

use super::paths::{binary_path, log_dir};

const SERVICE_NAME: &str = "llm-proxy.service";

pub fn unit_path() -> Result<PathBuf> {
    let home = home_dir().context("No home directory found")?;
    Ok(home.join(".config/systemd/user").join(SERVICE_NAME))
}

pub fn install(cfg_path: &Path, env_vars: HashMap<String, String>) -> Result<()> {
    let bin_path = binary_path()?;
    let log_dir = log_dir()?;
    let unit = unit_path()?;

    if let Some(parent) = unit.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut env_lines = String::new();
    for (k, v) in env_vars {
        env_lines.push_str(&format!("Environment=\"{}={}\"\n", k, v));
    }

    let unit_content = format!(
        r#"[Unit]
Description=LLM Proxy Service
After=network.target

[Service]
Type=simple
ExecStart={} run
WorkingDirectory={}
Restart=always
RestartSec=5
{}StandardOutput=append:{}/stdout.log
StandardError=append:{}/stderr.log

[Install]
WantedBy=default.target
"#,
        bin_path.display(),
        home_dir().context("No home directory")?.display(),
        env_lines,
        log_dir.display(),
        log_dir.display()
    );

    std::fs::write(&unit, unit_content)?;

    let _ = run_systemctl(&["--user", "daemon-reload"]);
    let _ = run_systemctl(&["--user", "enable", SERVICE_NAME]);

    info!("Installed systemd user service: {}", unit.display());
    info!("Config: {}", cfg_path.display());
    info!("Logs: {}", log_dir.display());
    info!("Run 'llm-proxy start' to start the service");
    Ok(())
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let output = std::process::Command::new("systemctl").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("systemctl failed: {}", stderr);
    }
    Ok(())
}

pub fn start() -> Result<()> {
    run_systemctl(&["--user", "start", SERVICE_NAME])?;
    info!("Service started");
    Ok(())
}

pub fn stop() -> Result<()> {
    let _ = run_systemctl(&["--user", "stop", SERVICE_NAME]);
    info!("Service stopped");
    Ok(())
}

pub fn restart() -> Result<()> {
    run_systemctl(&["--user", "restart", SERVICE_NAME])?;
    info!("Service restarted");
    Ok(())
}

pub fn status() -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["--user", "status", SERVICE_NAME])
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    println!("{}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

pub fn logs() -> Result<()> {
    let log_dir = log_dir()?;
    let out_log = log_dir.join("stdout.log");
    let err_log = log_dir.join("stderr.log");

    println!("Following logs (Ctrl+C to stop)...");
    println!("  stdout: {}", out_log.display());
    println!("  stderr: {}", err_log.display());

    let mut child = std::process::Command::new("tail")
        .args(["-f", out_log.to_str().unwrap(), err_log.to_str().unwrap()])
        .spawn()?;
    child.wait()?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let _ = stop();
    let _ = run_systemctl(&["--user", "disable", SERVICE_NAME]);
    let path = unit_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
        info!("Removed systemd unit: {}", path.display());
    }
    let _ = run_systemctl(&["--user", "daemon-reload"]);
    Ok(())
}
