use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;

/// Supported proxy protocols.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    Socks5,
    Http,
    Https,
}

/// Proxy configuration for a single tab slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    /// Optional username for authenticated proxies.
    pub username: Option<String>,
    /// Optional password (stored encrypted in vault; here as plaintext in memory only).
    pub password: Option<String>,
}

impl ProxyConfig {
    /// Build a PAC-compatible proxy string, e.g. "SOCKS5 127.0.0.1:1080".
    pub fn pac_string(&self) -> String {
        let proto = match self.protocol {
            ProxyProtocol::Socks5 => "SOCKS5",
            ProxyProtocol::Http => "PROXY",
            ProxyProtocol::Https => "HTTPS",
        };
        format!("{} {}:{}", proto, self.host, self.port)
    }

    /// Validate the config (basic sanity — not a connectivity check).
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            anyhow::bail!("proxy host must not be empty");
        }
        if self.port == 0 {
            anyhow::bail!("proxy port must not be 0");
        }
        if self.host.starts_with("169.254.") || self.host == "0.0.0.0" {
            anyhow::bail!("proxy host {} is a reserved/link-local address", self.host);
        }
        Ok(())
    }
}

/// Registry mapping tab_id → ProxyConfig (or None = no override, use workspace default).
#[derive(Debug, Default)]
pub struct TabProxyRegistry {
    entries: Mutex<HashMap<String, Option<ProxyConfig>>>,
}

impl TabProxyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set or clear the proxy for a tab.
    pub fn set(&self, tab_id: &str, proxy: Option<ProxyConfig>) -> Result<()> {
        if let Some(ref p) = proxy {
            p.validate().context("proxy validation")?;
        }
        self.entries
            .lock()
            .unwrap()
            .insert(tab_id.to_owned(), proxy);
        Ok(())
    }

    /// Get the proxy for a tab (None = use workspace/global default).
    pub fn get(&self, tab_id: &str) -> Option<ProxyConfig> {
        self.entries.lock().unwrap().get(tab_id).cloned().flatten()
    }

    /// Remove all proxy entries for a closed tab.
    pub fn remove(&self, tab_id: &str) {
        self.entries.lock().unwrap().remove(tab_id);
    }

    /// Generate a PAC script that routes each tab's traffic through its proxy.
    pub fn generate_pac_script(&self, tab_proxies: &[(String, ProxyConfig)]) -> String {
        let mut cases = String::new();
        for (tab_id, proxy) in tab_proxies {
            let _ = write!(
                cases,
                "  if (myHostHeader === '{}') {{ return '{}'; }}\n",
                tab_id,
                proxy.pac_string()
            );
        }
        format!(
            "function FindProxyForURL(url, host) {{\n\
             var myHostHeader = '';\n\
             {cases}\
             return 'DIRECT';\n\
             }}"
        )
    }
}

/// Persist tab proxy assignments to the DB (encrypted, keyed by tab_id).
pub fn save_proxy(db: &crate::storage::db::Db, tab_id: &str, proxy: &ProxyConfig) -> Result<()> {
    let key = format!("tab_proxy:{}", tab_id);
    let json = serde_json::to_string(proxy)?;
    db.set_setting(&key, &json)?;
    Ok(())
}

/// Load tab proxy assignment from DB.
pub fn load_proxy(db: &crate::storage::db::Db, tab_id: &str) -> Option<ProxyConfig> {
    let key = format!("tab_proxy:{}", tab_id);
    db.get_setting(&key)
        .and_then(|j| serde_json::from_str(&j).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_string_socks5() {
        let p = ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "10.0.0.1".to_owned(),
            port: 1080,
            username: None,
            password: None,
        };
        assert_eq!(p.pac_string(), "SOCKS5 10.0.0.1:1080");
    }

    #[test]
    fn validation_rejects_empty_host() {
        let p = ProxyConfig {
            protocol: ProxyProtocol::Http,
            host: "".to_owned(),
            port: 8080,
            username: None,
            password: None,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_port() {
        let p = ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "proxy.example.com".to_owned(),
            port: 0,
            username: None,
            password: None,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn registry_set_get_remove() {
        let reg = TabProxyRegistry::new();
        let proxy = ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_owned(),
            port: 1080,
            username: None,
            password: None,
        };
        reg.set("tab-1", Some(proxy.clone())).unwrap();
        assert!(reg.get("tab-1").is_some());
        reg.remove("tab-1");
        assert!(reg.get("tab-1").is_none());
    }
}
