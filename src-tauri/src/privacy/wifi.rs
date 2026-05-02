use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityType {
    /// No encryption — treat as untrusted.
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Unknown,
}

impl SecurityType {
    /// Returns true if this security type should trigger GhostPipe activation.
    pub fn is_untrusted(&self) -> bool {
        matches!(
            self,
            SecurityType::Open | SecurityType::Wep | SecurityType::Unknown
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInfo {
    pub ssid: String,
    /// BSSID (MAC address of the AP) — used together with SSID for trust keying.
    pub bssid: String,
    pub security: SecurityType,
    /// Signal strength in dBm (None if unavailable).
    pub signal_dbm: Option<i32>,
}

/// A trusted network identified by (SSID, BSSID) pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedNetwork {
    pub ssid: String,
    pub bssid: String,
    pub added_at: i64,
}

/// Detect the currently connected Wi-Fi network.
/// Returns None if not connected to Wi-Fi or detection fails.
pub fn detect_current_network() -> Option<WifiInfo> {
    #[cfg(target_os = "macos")]
    {
        macos_wifi()
    }

    #[cfg(target_os = "windows")]
    {
        windows_wifi()
    }

    #[cfg(target_os = "linux")]
    {
        linux_wifi()
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_wifi() -> Option<WifiInfo> {
    let out = std::process::Command::new("networksetup")
        .args(["-getairportnetwork", "en0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let ssid = text
        .trim()
        .strip_prefix("Current Wi-Fi Network: ")?
        .trim()
        .to_owned();

    let airport_out = std::process::Command::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .arg("-I")
    .output()
    .ok()?;
    let airport_text = String::from_utf8_lossy(&airport_out.stdout);

    let bssid = parse_kv(&airport_text, "BSSID").unwrap_or_else(|| "00:00:00:00:00:00".to_owned());
    let auth = parse_kv(&airport_text, "link auth")
        .unwrap_or_default()
        .to_lowercase();

    let security = if auth.contains("wpa3") {
        SecurityType::Wpa3
    } else if auth.contains("wpa2") {
        SecurityType::Wpa2
    } else if auth.contains("wpa") {
        SecurityType::Wpa
    } else if auth.contains("wep") {
        SecurityType::Wep
    } else if auth.is_empty() || auth.contains("open") {
        SecurityType::Open
    } else {
        SecurityType::Unknown
    };

    Some(WifiInfo {
        ssid,
        bssid,
        security,
        signal_dbm: None,
    })
}

#[cfg(target_os = "windows")]
fn windows_wifi() -> Option<WifiInfo> {
    let out = std::process::Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);

    let ssid = parse_kv(&text, "SSID")?;
    let bssid = parse_kv(&text, "BSSID").unwrap_or_else(|| "00:00:00:00:00:00".to_owned());
    let auth = parse_kv(&text, "Authentication")
        .unwrap_or_default()
        .to_lowercase();

    let security = if auth.contains("wpa3-personal") || auth.contains("wpa3-enterprise") {
        SecurityType::Wpa3
    } else if auth.contains("wpa2") {
        SecurityType::Wpa2
    } else if auth.contains("wpa") {
        SecurityType::Wpa
    } else if auth.contains("wep") {
        SecurityType::Wep
    } else if auth.contains("open") {
        SecurityType::Open
    } else {
        SecurityType::Unknown
    };

    Some(WifiInfo {
        ssid,
        bssid,
        security,
        signal_dbm: None,
    })
}

#[cfg(target_os = "linux")]
fn linux_wifi() -> Option<WifiInfo> {
    let out = std::process::Command::new("nmcli")
        .args([
            "-t",
            "--escape",
            "no",
            "-f",
            "ACTIVE,SSID,BSSID,SECURITY",
            "device",
            "wifi",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);

    for line in text.lines() {
        if !line.starts_with("yes:") {
            continue;
        }

        let rest = &line["yes:".len()..];

        let bssid_start = rest.find(|c: char| c.is_ascii_hexdigit()).and_then(|_| {
            rest.char_indices()
                .find(|&(i, _)| {
                    let candidate = rest.get(i..i + 17)?;
                    is_mac_address(candidate)
                })
                .map(|(i, _)| i)
        });

        let (ssid, bssid, sec_text) = if let Some(bi) = bssid_start {
            let ssid = rest[..bi.saturating_sub(1)].to_owned(); // strip trailing ':'
            let bssid = rest[bi..bi + 17].to_owned();
            let sec_text = rest.get(bi + 18..).unwrap_or("").to_lowercase();
            (ssid, bssid, sec_text)
        } else {
            let parts: Vec<&str> = rest.splitn(9, ':').collect();
            if parts.len() < 7 {
                continue;
            }
            let ssid = parts[0].to_owned();
            let bssid = parts[1..7].join(":");
            let sec_text = parts[7..].join(":").to_lowercase();
            (ssid, bssid, sec_text)
        };

        let security = if sec_text.contains("wpa3") {
            SecurityType::Wpa3
        } else if sec_text.contains("wpa2") {
            SecurityType::Wpa2
        } else if sec_text.contains("wpa") {
            SecurityType::Wpa
        } else if sec_text.contains("wep") {
            SecurityType::Wep
        } else if sec_text.trim().is_empty() {
            SecurityType::Open
        } else {
            SecurityType::Unknown
        };

        return Some(WifiInfo {
            ssid,
            bssid,
            security,
            signal_dbm: None,
        });
    }
    None
}

/// Returns true if `s` matches the pattern `XX:XX:XX:XX:XX:XX` (MAC address).
#[cfg(target_os = "linux")]
fn is_mac_address(s: &str) -> bool {
    if s.len() != 17 {
        return false;
    }
    let b = s.as_bytes();
    for i in 0..6 {
        let off = i * 3;
        if !b[off].is_ascii_hexdigit() || !b[off + 1].is_ascii_hexdigit() {
            return false;
        }
        if i < 5 && b[off + 2] != b':' {
            return false;
        }
    }
    true
}

fn parse_kv(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find(|l| l.trim().to_lowercase().starts_with(&key.to_lowercase()))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|v| v.trim().to_owned())
}

/// Check whether a given (ssid, bssid) pair is in the trusted networks list.
pub fn is_trusted(db: &crate::storage::db::Db, ssid: &str, bssid: &str) -> bool {
    trusted_networks(db)
        .iter()
        .any(|n| n.ssid == ssid && n.bssid == bssid)
}

/// Add a network to the trusted list.
pub fn trust_network(db: &crate::storage::db::Db, ssid: &str, bssid: &str) -> Result<()> {
    let mut networks = trusted_networks(db);
    let entry = TrustedNetwork {
        ssid: ssid.to_owned(),
        bssid: bssid.to_owned(),
        added_at: crate::storage::db::unix_now(),
    };
    if !networks
        .iter()
        .any(|n| n.ssid == entry.ssid && n.bssid == entry.bssid)
    {
        networks.push(entry);
    }
    persist_trusted_networks(db, &networks)
}

/// Remove a network from the trusted list.
pub fn distrust_network(db: &crate::storage::db::Db, ssid: &str, bssid: &str) -> Result<()> {
    let networks: Vec<TrustedNetwork> = trusted_networks(db)
        .into_iter()
        .filter(|n| !(n.ssid == ssid && n.bssid == bssid))
        .collect();
    persist_trusted_networks(db, &networks)
}

fn trusted_networks(db: &crate::storage::db::Db) -> Vec<TrustedNetwork> {
    db.get_setting("wifi_trusted_networks")
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

fn persist_trusted_networks(
    db: &crate::storage::db::Db,
    networks: &[TrustedNetwork],
) -> Result<()> {
    db.set_setting("wifi_trusted_networks", &serde_json::to_string(networks)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_network_is_untrusted() {
        assert!(SecurityType::Open.is_untrusted());
        assert!(SecurityType::Wep.is_untrusted());
        assert!(SecurityType::Unknown.is_untrusted());
    }

    #[test]
    fn wpa2_is_trusted_security() {
        assert!(!SecurityType::Wpa2.is_untrusted());
        assert!(!SecurityType::Wpa3.is_untrusted());
    }
}
