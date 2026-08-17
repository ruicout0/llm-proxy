use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::sync::RwLock;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Billable,
    Discovery,
    Probe,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostSource {
    Reported,
    Estimated,
    None,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct ModelUsage {
    pub requests: u64,
    #[serde(default)]
    pub cost: BTreeMap<String, f64>,
    #[serde(default)]
    pub cost_estimated: BTreeMap<String, f64>,
    #[serde(default)]
    pub tokens: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct ProviderUsage {
    pub requests: u64,
    #[serde(default)]
    pub models: BTreeMap<String, ModelUsage>,
    #[serde(default)]
    pub totals: BTreeMap<String, f64>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
pub struct GroupUsage {
    pub requests: u64,
    #[serde(default)]
    pub models: BTreeMap<String, ModelUsage>,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderUsage>,
    #[serde(default)]
    pub totals: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct UsageStoreData {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, GroupUsage>,
    #[serde(default)]
    pub global_requests: u64,
    #[serde(default)]
    pub global_totals: BTreeMap<String, f64>,
    pub last_updated: Option<u64>,
}

fn default_schema_version() -> u32 {
    2
}

impl Default for UsageStoreData {
    fn default() -> Self {
        Self {
            schema_version: 2,
            groups: BTreeMap::new(),
            global_requests: 0,
            global_totals: BTreeMap::new(),
            last_updated: None,
        }
    }
}

impl UsageStoreData {
    pub fn touch_last_updated(&mut self) {
        self.last_updated = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
    }
}

pub struct UsageStore {
    data: RwLock<UsageStoreData>,
    path: PathBuf,
}

impl UsageStore {
    pub fn new(path: PathBuf) -> Self {
        let data = if path.exists() {
            Self::load_and_migrate(&path).unwrap_or_default()
        } else {
            UsageStoreData::default()
        };
        Self {
            data: RwLock::new(data),
            path,
        }
    }

    fn load_and_migrate(path: &PathBuf) -> Result<UsageStoreData> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read usage store: {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse usage store JSON: {}", path.display()))?;

        let version = value.get("schema_version").and_then(|v| v.as_u64()).unwrap_or(1);
        if version >= 2 {
            let data: UsageStoreData = serde_json::from_value(value)?;
            return Ok(data);
        }

        // Migrate from Schema v1 to v2
        let backup_path = format!("{}.v1.bak", path.display());
        let _ = std::fs::write(&backup_path, &content);

        let mut data: UsageStoreData = serde_json::from_value(value.clone()).unwrap_or_default();
        data.schema_version = 2;

        // Populate provider dimension under "default" if missing
        for group in data.groups.values_mut() {
            if group.providers.is_empty() && !group.models.is_empty() {
                let prov_usage = ProviderUsage {
                    requests: group.requests,
                    models: group.models.clone(),
                    totals: group.totals.clone(),
                };
                group.providers.insert("default".to_string(), prov_usage);
            }
        }

        // Recompute global totals
        let mut global_totals = BTreeMap::new();
        for group in data.groups.values() {
            for (currency, amount) in &group.totals {
                *global_totals.entry(currency.clone()).or_default() += amount;
            }
        }
        data.global_totals = global_totals;
        data.touch_last_updated();

        let json = serde_json::to_string_pretty(&data)?;
        let _ = std::fs::write(path, json);

        Ok(data)
    }

    pub async fn record(
        &self,
        group: &str,
        model: &str,
        cost: Option<(f64, String)>,
        tokens: BTreeMap<String, u64>,
    ) -> Result<()> {
        self.record_with_provider(group, "default", model, cost, None, tokens).await
    }

    pub async fn record_with_provider(
        &self,
        group: &str,
        provider: &str,
        canonical_model: &str,
        cost_reported: Option<(f64, String)>,
        cost_estimated: Option<(f64, String)>,
        tokens: BTreeMap<String, u64>,
    ) -> Result<()> {
        let mut data = self.data.write().await;

        let is_probe = group == "__probe";
        if !is_probe {
            data.global_requests += 1;
        }

        let group_entry = data.groups.entry(group.to_string()).or_default();
        group_entry.requests += 1;

        // Group-level flat model entry for backwards compatibility & quick lookup
        let model_usage = group_entry.models.entry(canonical_model.to_string()).or_default();
        model_usage.requests += 1;

        // Provider-level model entry
        let provider_entry = group_entry.providers.entry(provider.to_string()).or_default();
        provider_entry.requests += 1;
        let prov_model_usage = provider_entry.models.entry(canonical_model.to_string()).or_default();
        prov_model_usage.requests += 1;

        if let Some((amount, currency)) = cost_reported {
            if amount > 0.0 {
                *model_usage.cost.entry(currency.clone()).or_default() += amount;
                *prov_model_usage.cost.entry(currency.clone()).or_default() += amount;
                *group_entry.totals.entry(currency.clone()).or_default() += amount;
                *provider_entry.totals.entry(currency.clone()).or_default() += amount;
            }
        }

        if let Some((amount, currency)) = cost_estimated {
            if amount > 0.0 {
                *model_usage.cost_estimated.entry(currency.clone()).or_default() += amount;
                *prov_model_usage.cost_estimated.entry(currency.clone()).or_default() += amount;
            }
        }

        for (token_type, count) in tokens {
            if count > 0 {
                *model_usage.tokens.entry(token_type.clone()).or_default() += count;
                *prov_model_usage.tokens.entry(token_type.clone()).or_default() += count;
                *group_entry
                    .totals
                    .entry(format!("{}_tokens", token_type))
                    .or_default() += count as f64;
                *provider_entry
                    .totals
                    .entry(format!("{}_tokens", token_type))
                    .or_default() += count as f64;
            }
        }

        // Recalculate global totals excluding __probe
        let mut global_totals = BTreeMap::new();
        for (g_name, g) in &data.groups {
            if g_name == "__probe" {
                continue;
            }
            for (currency, amount) in &g.totals {
                *global_totals.entry(currency.clone()).or_default() += amount;
            }
        }
        data.global_totals = global_totals;

        data.touch_last_updated();
        self.persist_sync(&data)?;
        Ok(())
    }

    pub async fn get(&self) -> UsageStoreData {
        self.data.read().await.clone()
    }

    pub async fn reset(&self) -> Result<()> {
        let mut data = self.data.write().await;
        *data = UsageStoreData::default();
        data.touch_last_updated();
        self.persist_sync(&data)?;
        Ok(())
    }

    fn persist_sync(&self, data: &UsageStoreData) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create usage store dir: {}", parent.display())
            })?;
        }
        let json = serde_json::to_string_pretty(data)?;
        std::fs::write(&self.path, json)
            .with_context(|| format!("Failed to write usage store: {}", self.path.display()))?;
        Ok(())
    }
}

pub fn resolve_usage_group(headers: &hyper::HeaderMap) -> String {
    if let Some(value) = headers.get("x-usage-group").and_then(|v| v.to_str().ok()) {
        if !value.is_empty() {
            return value.to_string();
        }
    }

    if let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let normalized = value.trim().to_lowercase();
        if !normalized.is_empty() {
            return format!("auth:{}", sha256_hex(normalized.as_bytes()));
        }
    }

    if let Some(value) = headers.get("x-apikey").and_then(|v| v.to_str().ok()) {
        if !value.is_empty() {
            return format!("apikey:{}", sha256_hex(value.as_bytes()));
        }
    }

    "default".to_string()
}

pub fn sha256_hex(input: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub fn usage_dashboard_html() -> &'static str {
    r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LLM Proxy Usage</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #1e293b;
      --panel-2: #27354f;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent-2: #818cf8;
      --success: #34d399;
      --danger: #f87171;
      --border: #334155;
      --radius: 14px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
    header { margin-bottom: 28px; }
    h1 { margin: 0 0 6px; font-size: 1.75rem; letter-spacing: -0.02em; }
    .subtitle { color: var(--muted); font-size: 0.95rem; }
    .refresh { color: var(--muted); font-size: 0.85rem; margin-top: 8px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-bottom: 28px; }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.25);
    }
    .card h3 { margin: 0 0 6px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
    .card .value { font-size: 1.7rem; font-weight: 700; color: var(--text); }
    .card .value.accent { color: var(--accent); }
    .card .value.success { color: var(--success); }
    .card .value.danger { color: var(--danger); }
    section { margin-bottom: 28px; }
    h2 { font-size: 1.15rem; margin: 0 0 14px; display: flex; align-items: center; gap: 8px; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: var(--panel-2); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,0.03); }
    .tag { display: inline-block; padding: 3px 8px; border-radius: 999px; background: var(--panel-2); font-size: 0.75rem; color: var(--accent); border: 1px solid var(--border); }
    .empty { color: var(--muted); font-style: italic; padding: 20px; text-align: center; }
    .right { text-align: right; }
    .last-updated { color: var(--muted); font-size: 0.8rem; margin-top: 12px; }
    @media (max-width: 600px) {\n      .container { padding: 20px 14px; }\n      th, td { padding: 10px 12px; font-size: 0.85rem; }\n    }\n  </style>\n</head>\n<body>\n  <div class=\"container\">\n    <header>\n      <h1>🧠 LLM Proxy Usage</h1>\n      <div class=\"subtitle\">Live cost and token totals from proxied requests</div>\n      <div class=\"refresh\">Auto-refresh every 30s · <a href=\"/llm-proxy/usage\" style=\"color:var(--accent)\">JSON API</a></div>\n    </header>\n\n    <div class=\"grid\" id=\"summary\">\n      <div class=\"card\"><h3>Total Requests</h3><div class=\"value accent\" id=\"total-requests\">–</div></div>\n      <div class=\"card\"><h3>Total Cost</h3><div class=\"value success\" id=\"total-cost\">–</div></div>\n      <div class=\"card\"><h3>Active Groups</h3><div class=\"value\" id=\"active-groups\">–</div></div>\n      <div class=\"card\"><h3>Models Used</h3><div class=\"value\" id=\"models-used\">–</div></div>\n    </div>\n\n    <section>\n      <h2>📊 Per-Group / Per-Model</h2>\n      <table id=\"details-table\">\n        <thead>\n          <tr><th>Group</th><th>Model</th><th class=\"right\">Requests</th><th class=\"right\">Cost</th><th class=\"right\">Tokens</th></tr>\n        </thead>\n        <tbody id=\"details-body\"><tr><td colspan=\"5\" class=\"empty\">No usage recorded yet.</td></tr></tbody>\n      </table>\n      <div class=\"last-updated\" id=\"last-updated\"></div>\n    </section>\n  </div>\n\n  <script>\n    const fmt = (n) => typeof n === 'number' ? n.toLocaleString() : '–';\n    const fmtCost = (n, c) => typeof n === 'number' ? `${n.toFixed(6)} ${c || 'USD'}` : '–';\n\n    async function load() {\n      try {\n        const res = await fetch('/llm-proxy/usage');\n        const data = await res.json();\n\n        document.getElementById('total-requests').textContent = fmt(data.global_requests);\n\n        const costEntries = Object.entries(data.global_totals || {}).filter(([k]) => !k.endsWith('_tokens'));\n        document.getElementById('total-cost').textContent = costEntries.length\n          ? costEntries.map(([c, a]) => fmtCost(a, c)).join(' + ')\n          : '$0.000000';\n\n        const groups = Object.entries(data.groups || {});\n        document.getElementById('active-groups').textContent = groups.length;\n\n        let modelCount = 0;\n        const tbody = document.getElementById('details-body');\n        tbody.innerHTML = '';\n\n        if (groups.length === 0) {\n          tbody.innerHTML = '<tr><td colspan=\"5\" class=\"empty\">No usage recorded yet.</td></tr>';\n        } else {\n          for (const [groupName, group] of groups) {\n            const models = Object.entries(group.models || {});\n            modelCount += models.length;\n            for (const [modelName, model] of models) {\n              const cost = Object.entries(model.cost || {})\n                .filter(([k]) => !k.endsWith('_tokens'))\n                .map(([c, a]) => fmtCost(a, c))\n                .join(' + ') || '–';\n              const tokens = Object.entries(model.tokens || {})\n                .map(([t, n]) => `${t}: ${fmt(n)}`)\n                .join('<br>') || '–';\n              const row = document.createElement('tr');\n              row.innerHTML = `<td><span class=\"tag\">${groupName}</span></td><td>${modelName}</td><td class=\"right\">${fmt(model.requests)}</td><td class=\"right\">${cost}</td><td class=\"right\">${tokens}</td>`;\n              tbody.appendChild(row);\n            }\n          }\n        }\n        document.getElementById('models-used').textContent = modelCount;\n\n        const ts = data.last_updated\n          ? new Date(data.last_updated * 1000).toLocaleString()\n          : 'never';\n        document.getElementById('last-updated').textContent = 'Last updated: ' + ts;\n      } catch (e) {\n        console.error(e);\n      }\n    }\n\n    load();\n    setInterval(load, 30000);\n  </script>\n</body>\n</html>"##
}
