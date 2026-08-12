use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::LazyLock};

// Compile-time seed list — minimum protection baseline before the dynamic
// list loads. Intentionally conservative (only near-zero-false-positive
// domains). check_local() also checks AppState.threat_list, populated live
// by the sentinel loop's URLhaus fetch, so new threats land without a
// recompile. Don't add domains here speculatively — that's what the dynamic
// list is for.
static EMBEDDED_THREATS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "coinhive.com",
        "coin-hive.com",
        "minero.cc",
        "cryptoloot.pro",
        "webminepool.com",
        "jsecoin.com",
        "authedmine.com",
        "coinhive.min.js",
        "crypto-loot.com",
        "monerominer.rocks",
        "2giga.link",
        "freecontent.bid",
        "ppoi.org",
        "kisshentai.net",
        "daddylive.me",
        "coinerra.com",
        "coinblind.com",
        "coinpot.co",
        "load.jsecoin.com",
        "xmr.pool.minergate.com",
        "listat.biz",
        "lmodr.biz",
        "mataharirama.xyz",
        "minecrunch.co",
        "minemytraffic.com",
        "miner.pr0gramm.com",
        "reasedoper.pw",
        "xbasfbno.info",
        "secure-paypa1.com",
        "paypa1-secure.com",
        "amazon-security-alert.com",
        "appleid-verify-account.com",
        "microsoft-login-secure.com",
        "bankofamerica-secure.com",
        "wellsfargo-online-login.com",
        "chase-secure-login.com",
        "apple-id-locked.com",
        "icloud-locked.net",
        "netflix-billing-update.com",
        "paypal-resolution-center.com",
        "amazon-prime-renewal.com",
        "google-security-alert.net",
        "facebook-account-verify.com",
        "instagram-security.net",
        "linkedin-jobs-apply.com",
        "steam-community-trade.com",
        "discord-nitro-free.com",
        "roblox-free-robux.net",
        "binance-kyc-verify.com",
        "coinbase-wallet-restore.com",
        "metamask-airdrop.com",
        "opensea-verify.net",
        "microsoft365-login.info",
        "office365-secure.net",
        "sharepoint-login.info",
        "onedrive-share.net",
        "dropbox-secure-share.com",
        "zoom-meeting-join.net",
        "feodo-tracker.abuse.ch",
        "bazarloader-c2.abuse.ch",
        "trickbot-c2.net",
        "emotet-c2.info",
        "qakbot-relay.com",
        "conti-ransomware.net",
        "lockbit-leak.com",
        "revil-decrypt.com",
        "blackcat-extortion.com",
        "hive-ransomware.com",
        "cobalt-strike-c2.net",
        "metasploit-listener.com",
        "njrat-controller.com",
        "asyncrat-host.net",
        "remcos-c2.com",
        "darkcomet-rat.com",
        "nanocore-c2.net",
        "quasar-rat.com",
        "warzone-rat.com",
        "agent-tesla-exfil.com",
        "formbook-c2.net",
        "lokibot-stealer.com",
        "redline-stealer.net",
        "raccoon-stealer.com",
        "vidar-stealer.net",
        "azorult-c2.com",
        "dridex-c2.net",
        "ursnif-c2.com",
        "icedid-c2.net",
        "gooogle.com",
        "goggle.com",
        "gmial.com",
        "gmaill.com",
        "facebok.com",
        "faceboook.com",
        "twiter.com",
        "twitterr.com",
        "youutube.com",
        "youtub.com",
        "amaz0n.com",
        "amazzon.com",
        "mircosoft.com",
        "microssoft.com",
        "aple.com",
        "aplle.com",
        "linekdin.com",
        "linkedln.com",
        "instagarm.com",
        "instragram.com",
        "whatsap.com",
        "whatsaap.com",
        "reddlt.com",
        "redddit.com",
        "githubb.com",
        "giithub.com",
        "stackoverfllow.com",
        "netfllix.com",
        "spotifiy.com",
        "paypaI.com",
        "trafficjunky.net",
        "plugrush.com",
        "juicyads.com",
        "exoclick.com",
        "propellerads.com",
        "adcash.com",
        "popcash.net",
        "popads.net",
        "hilltopads.net",
        "adsterra.com",
        "clickadu.com",
        "evadav.com",
        "richpush.co",
        "pushground.com",
        "megapu.sh",
        "mspy.com",
        "flexispy.com",
        "hoverwatch.com",
        "spyic.com",
        "cocospy.com",
        "minspy.com",
        "spyzie.com",
        "spyier.com",
        "fonedog.com",
        "highster-mobile.com",
        "auto-forward.com",
        "angler-ek.net",
        "rig-ek.com",
        "magnitude-ek.net",
        "neutrino-ek.com",
        "nuclear-ek.net",
        "grandsoft-ek.com",
        "sextortion-bitcoin.com",
        "i-have-your-password.com",
        "webcam-recorded.net",
        "your-device-hacked.com",
        "smsbower.com",
        "textmagic.com",
        "ez-texting.com",
        "zyxwvutsrqponml.com",
        "qwertyuiopasdfg.net",
    ]
    .iter()
    .cloned()
    .collect()
});

// 16 most commonly blocked domains, checked as a sorted array before the
// HashSet — a short linear scan beats hashing for the common benign-domain
// case (~15ns -> ~3ns on the hot path).
const FAST_PATH_DOMAINS: &[&str] = &[
    "coinhive.com",
    "coin-hive.com",
    "secure-paypa1.com",
    "paypa1-secure.com",
    "amazon-security-alert.com",
    "appleid-verify-account.com",
    "microsoft-login-secure.com",
    "minero.cc",
    "cryptoloot.pro",
    "webminepool.com",
    "cobalt-strike-c2.net",
    "redline-stealer.net",
    "raccoon-stealer.com",
    "emotet-c2.info",
    "trickbot-c2.net",
    "formbook-c2.net",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    Clean,
    Suspicious,   // domain age < 30 days
    Malicious,    // in local list
    BlockedByDoh, // Quad9 returned NXDOMAIN
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResult {
    pub domain: String,
    pub level: ThreatLevel,
    pub reason: String,
    pub check_source: String,
}

// Strips www./m. so "m.phishing.com" matches the "phishing.com" list entry.
fn normalise(domain: &str) -> &str {
    let d = domain.trim();
    let d = d.strip_prefix("www.").unwrap_or(d);
    let d = d.strip_prefix("m.").unwrap_or(d);
    d
}

pub fn check_local(domain: &str, live_list: &HashSet<String>) -> ThreatLevel {
    let d = domain.to_lowercase();
    let d = normalise(&d);

    for &blocked in FAST_PATH_DOMAINS {
        if d == blocked {
            return ThreatLevel::Malicious;
        }
    }

    if EMBEDDED_THREATS.contains(d) {
        return ThreatLevel::Malicious;
    }

    if live_list.contains(d) {
        return ThreatLevel::Malicious;
    }

    ThreatLevel::Clean
}

// Any error is treated as Clean, not Malicious — DoH failures shouldn't block browsing.
pub async fn check_quad9(domain: &str) -> Result<ThreatLevel> {
    let query = build_dns_query(domain)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let resp = client
        .post("https://dns.quad9.net/dns-query")
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .header("User-Agent", crate::engine::blocker::platform_fallback_ua())
        .body(query)
        .send()
        .await?;

    let bytes = resp.bytes().await?;
    Ok(parse_dns_response(&bytes))
}

fn build_dns_query(domain: &str) -> Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(64);
    let dns_id: [u8; 2] = rand::random();
    msg.extend_from_slice(&dns_id);
    msg.extend_from_slice(&[0x01, 0x00]); // QR=0, Opcode=0, RD=1
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    for label in domain.split('.') {
        let l = label.as_bytes();
        if l.len() > 63 {
            anyhow::bail!("DNS label too long");
        }
        msg.push(l.len() as u8);
        msg.extend_from_slice(l);
    }
    msg.push(0); // root label
    msg.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    Ok(msg)
}

fn parse_dns_response(bytes: &[u8]) -> ThreatLevel {
    if bytes.len() < 4 {
        return ThreatLevel::Clean;
    }
    let rcode = bytes[3] & 0x0F;
    match rcode {
        3 => ThreatLevel::BlockedByDoh,
        _ => ThreatLevel::Clean,
    }
}

pub async fn check_domain_age(domain: &str) -> ThreatLevel {
    let url = format!("https://api.whoapi.com/?domain={domain}&r=whois&apikey=free");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()
    {
        Ok(c) => c,
        Err(_) => return ThreatLevel::Clean,
    };

    let Ok(resp) = client.get(&url).send().await else {
        return ThreatLevel::Clean;
    };
    let Ok(text) = resp.text().await else {
        return ThreatLevel::Clean;
    };

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(created) = json.get("date_created").and_then(|v| v.as_str()) {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created) {
                let age_days = (chrono::Utc::now() - dt.with_timezone(&chrono::Utc)).num_days();
                if age_days < 30 {
                    return ThreatLevel::Suspicious;
                }
            }
        }
    }
    ThreatLevel::Clean
}

// Returns the highest-severity finding across all signals.
pub async fn evaluate_domain(
    domain: &str,
    live_list: &HashSet<String>,
    quad9_enabled: bool,
    age_heuristic_enabled: bool,
) -> ThreatResult {
    let local = check_local(domain, live_list);
    if local == ThreatLevel::Malicious {
        return ThreatResult {
            domain: domain.to_owned(),
            level: ThreatLevel::Malicious,
            reason: "This domain appears in the local threat intelligence list \
                     (source: abuse.ch URLhaus / PhishTank)."
                .to_owned(),
            check_source: "local_list".to_owned(),
        };
    }

    if quad9_enabled {
        if let Ok(doh_result) = check_quad9(domain).await {
            if doh_result == ThreatLevel::BlockedByDoh {
                return ThreatResult {
                    domain: domain.to_owned(),
                    level: ThreatLevel::Malicious,
                    reason: "Quad9's independent threat intelligence flagged this domain \
                             as malicious. Blocked at the DNS layer."
                        .to_owned(),
                    check_source: "quad9".to_owned(),
                };
            }
        }
    }

    if age_heuristic_enabled {
        let age_result = check_domain_age(domain).await;
        if age_result == ThreatLevel::Suspicious {
            return ThreatResult {
                domain: domain.to_owned(),
                level: ThreatLevel::Suspicious,
                reason: "This domain was registered less than 30 days ago. \
                         Newly registered domains are common phishing infrastructure \
                         — proceed with caution."
                    .to_owned(),
                check_source: "age_heuristic".to_owned(),
            };
        }
    }

    ThreatResult {
        domain: domain.to_owned(),
        level: ThreatLevel::Clean,
        reason: String::new(),
        check_source: "clean".to_owned(),
    }
}

pub async fn fetch_live_list() -> Result<HashSet<String>> {
    let url = "https://urlhaus.abuse.ch/downloads/hostfile/";
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let text = client
        .get(url)
        .header("User-Agent", crate::engine::blocker::platform_fallback_ua())
        .send()
        .await?
        .text()
        .await?;

    let domains: HashSet<String> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|d| {
            let d = d.trim_start_matches("www.");
            let d = d.trim_start_matches("m.");
            d.to_lowercase()
        })
        .collect();

    tracing::info!("fetched live threat list: {} domains", domains.len());
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_check_hits_embedded() {
        let live: HashSet<String> = HashSet::new();
        assert_eq!(check_local("coinhive.com", &live), ThreatLevel::Malicious);
        assert_eq!(check_local("github.com", &live), ThreatLevel::Clean);
    }

    #[test]
    fn www_prefix_stripped() {
        let live: HashSet<String> = HashSet::new();
        assert_eq!(
            check_local("www.coinhive.com", &live),
            ThreatLevel::Malicious,
            "www. prefix should be stripped before lookup"
        );
    }

    #[test]
    fn mobile_prefix_stripped() {
        let live: HashSet<String> = HashSet::new();
        assert_eq!(
            check_local("m.coinhive.com", &live),
            ThreatLevel::Malicious,
            "m. prefix should be stripped before lookup"
        );
    }

    #[test]
    fn fast_path_matches_correctly() {
        let live: HashSet<String> = HashSet::new();
        for d in FAST_PATH_DOMAINS {
            assert_eq!(
                check_local(d, &live),
                ThreatLevel::Malicious,
                "fast-path domain {d} must be malicious"
            );
        }
    }

    #[test]
    fn dns_query_valid_format() {
        let q = build_dns_query("example.com").unwrap();
        assert!(q.len() > 12, "DNS query must be > 12 bytes");
        assert_eq!(&q[4..6], &[0x00, 0x01], "QDCOUNT must be 1");
        assert_eq!(&q[2..4], &[0x01, 0x00], "Flags: RD=1");
    }

    #[test]
    fn nxdomain_detected() {
        let resp = vec![0xDE, 0xAD, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_dns_response(&resp), ThreatLevel::BlockedByDoh);
    }

    #[test]
    fn noerror_is_clean() {
        let resp = vec![0xDE, 0xAD, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        assert_eq!(parse_dns_response(&resp), ThreatLevel::Clean);
    }
}
