use anyhow::{Context, Result};
use dirs::home_dir;
use plist::{Dictionary, Value as PlistValue};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

use super::paths::{binary_path, log_dir, SERVICE_LABEL};

pub fn plist_path() -> Result<PathBuf> {
    let home = home_dir().context("No home directory")?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", SERVICE_LABEL)))
}

pub fn install(cfg_path: &Path, env_vars: HashMap<String, String>) -> Result<()> {
    let bin_path = binary_path()?;
    let log_dir = log_dir()?;
    let out_log = log_dir.join("stdout.log");
    let err_log = log_dir.join("stderr.log");

    let mut env_dict = Dictionary::new();
    for (k, v) in env_vars {
        env_dict.insert(k, PlistValue::String(v));
    }

    let mut plist = Dictionary::new();
    plist.insert(
        "Label".to_string(),
        PlistValue::String(SERVICE_LABEL.to_string()),
    );
    plist.insert(
        "ProgramArguments".to_string(),
        PlistValue::Array(vec![
            PlistValue::String(bin_path.to_string_lossy().to_string()),
            PlistValue::String("run".to_string()),
        ]),
    );
    plist.insert("RunAtLoad".to_string(), PlistValue::Boolean(true));
    plist.insert("KeepAlive".to_string(), PlistValue::Boolean(true));
    plist.insert(
        "StandardOutPath".to_string(),
        PlistValue::String(out_log.to_string_lossy().to_string()),
    );
    plist.insert(
        "StandardErrorPath".to_string(),
        PlistValue::String(err_log.to_string_lossy().to_string()),
    );
    plist.insert(
        "EnvironmentVariables".to_string(),
        PlistValue::Dictionary(env_dict),
    );
    plist.insert(
        "WorkingDirectory".to_string(),
        PlistValue::String(
            home_dir()
                .context("No home directory")?
                .to_string_lossy()
                .to_string(),
        ),
    );

    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    plist::Value::Dictionary(plist).to_file_xml(&path)?;

    info!("Installed launchd service: {}", path.display());
    info!("Config: {}", cfg_path.display());
    info!("Logs: {}", log_dir.display());
    info!("Run 'llm-proxy start' to start the service");
    Ok(())
}

fn run_launchctl(args: &[&str]) -> Result<()> {
    let output = std::process::Command::new("launchctl")
        .args(args)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("launchctl failed: {}", stderr);
    }
    Ok(())
}

pub fn start() -> Result<()> {
    run_launchctl(&["load", "-w", plist_path()?.to_str().unwrap()])?;
    info!("Service started");
    Ok(())
}

pub fn stop() -> Result<()> {
    let _ = run_launchctl(&["unload", "-w", plist_path()?.to_str().unwrap()]);
    info!("Service stopped");
    Ok(())
}

pub fn restart() -> Result<()> {
    stop()?;
    std::thread::sleep(Duration::from_secs(1));
    start()?;
    Ok(())
}

pub fn status() -> Result<()> {
    let output = std::process::Command::new("launchctl")
        .args(["list", SERVICE_LABEL])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains(SERVICE_LABEL) {
        info!("Service is LOADED");
        println!("{}", stdout);
    } else {
        info!("Service is NOT loaded");
    }
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
    let path = plist_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
        info!("Removed plist: {}", path.display());
    }
    Ok(())
}
