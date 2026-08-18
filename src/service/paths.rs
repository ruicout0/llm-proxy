use anyhow::{Context, Result};
use dirs::home_dir;
use std::path::PathBuf;

pub const SERVICE_LABEL: &str = "com.user.llm-proxy";

pub fn log_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    let dir = home_dir()
        .context("No home directory found")?
        .join("Library/Logs/llm-proxy");

    #[cfg(target_os = "linux")]
    let dir = dirs::state_dir()
        .unwrap_or_else(|| home_dir().unwrap().join(".local/state"))
        .join("llm-proxy/logs");

    #[cfg(target_os = "windows")]
    let dir = dirs::data_local_dir()
        .unwrap_or_else(|| home_dir().unwrap().join("AppData/Local"))
        .join("llm-proxy/logs");

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let dir = home_dir()
        .context("No home directory found")?
        .join(".llm-proxy/logs");

    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn binary_path() -> Result<PathBuf> {
    let current_exe = std::env::current_exe()?;
    let exe_name = if cfg!(windows) { "llm-proxy.exe" } else { "llm-proxy" };
    
    if current_exe.file_name().and_then(|s| s.to_str()) == Some(exe_name) {
        Ok(current_exe)
    } else {
        #[cfg(windows)]
        let bin_path = dirs::data_local_dir()
            .unwrap_or_else(|| home_dir().unwrap().join("AppData/Local"))
            .join("llm-proxy/bin")
            .join(exe_name);

        #[cfg(not(windows))]
        let bin_path = home_dir()
            .context("No home directory found")?
            .join(".local/bin/llm-proxy");

        Ok(bin_path)
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    #[cfg(windows)]
    let dir = dirs::config_dir()
        .unwrap_or_else(|| home_dir().unwrap().join("AppData/Roaming"))
        .join("llm-proxy");

    #[cfg(not(windows))]
    let dir = home_dir()
        .context("No home directory found")?
        .join(".config/llm-proxy");

    Ok(dir.join("config.toml"))
}
