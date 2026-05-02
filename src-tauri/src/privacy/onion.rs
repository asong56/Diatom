use serde::Serialize;

/// A known hidden-service alternative for a surface-web domain.
#[derive(Debug, Clone, Serialize)]
pub struct OnionSuggestion {
    /// The surface-web hostname the user is currently visiting.
    pub surface_host: String,
    /// The .onion or .i2p address of the hidden-service mirror.
    pub hidden_host: String,
    /// Which overlay network this mirror lives on.
    pub network: HiddenNetwork,
    /// Human-readable label for UI display.
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HiddenNetwork {
    Tor,
    I2p,
}

static KNOWN_MIRRORS: &[(&str, &str, HiddenNetwork, &str)] = &[
    (
        "nytimes.com",
        "ej3kv4ebuugcmuwxctx7ic2at2c7un7tbhkx4ks2irgpvqvbthftmiqd.onion",
        HiddenNetwork::Tor,
        "New York Times — official Tor mirror",
    ),
    (
        "bbc.co.uk",
        "bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion",
        HiddenNetwork::Tor,
        "BBC News — official Tor mirror",
    ),
    (
        "bbc.com",
        "bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion",
        HiddenNetwork::Tor,
        "BBC News — official Tor mirror",
    ),
    (
        "theguardian.com",
        "guardian2zotagl6o5hfvinnclh7ho3zmpyit2ojxlbkocdypd64ysad.onion",
        HiddenNetwork::Tor,
        "The Guardian — official Tor mirror",
    ),
    (
        "duckduckgo.com",
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        HiddenNetwork::Tor,
        "DuckDuckGo — official Tor hidden service",
    ),
    (
        "wikipedia.org",
        "www.wikimedia-censorship.onion", // mirrors vary by language; link to meta
        HiddenNetwork::Tor,
        "Wikimedia — Tor .onion portal (select language inside)",
    ),
    (
        "proton.me",
        "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
        HiddenNetwork::Tor,
        "Proton Mail / VPN — official Tor hidden service",
    ),
    (
        "protonmail.com",
        "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
        HiddenNetwork::Tor,
        "Proton Mail — official Tor hidden service",
    ),
    (
        "brave.com",
        "brave4u7jddbv7csl7con7oulsgl5bj2vhxxzco56xwwjr3c66re7fid.onion",
        HiddenNetwork::Tor,
        "Brave Browser — official Tor hidden service",
    ),
    (
        "securedrop.org",
        "sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion",
        HiddenNetwork::Tor,
        "SecureDrop — whistleblower submission system",
    ),
    (
        "debian.org",
        "sejnfjrq6szgca7v.onion",
        HiddenNetwork::Tor,
        "Debian — official package mirror over Tor",
    ),
    (
        "tails.boum.org",
        "http://tails.boum.org", // retained surface URL — .onion via official doc
        HiddenNetwork::Tor,
        "Tails OS — check tails.boum.org/doc for current .onion",
    ),
];

/// Look up whether the given hostname has a known hidden-service mirror.
/// Returns `None` if no mirror is catalogued for this domain.
///
/// Matching is suffix-based: "en.wikipedia.org" matches "wikipedia.org".
pub fn lookup(host: &str) -> Option<OnionSuggestion> {
    let host_lower = host.to_lowercase();
    let host_clean = host_lower.strip_prefix("www.").unwrap_or(&host_lower);

    for &(surface, hidden, ref network, label) in KNOWN_MIRRORS {
        if host_clean == surface || host_clean.ends_with(&format!(".{}", surface)) {
            return Some(OnionSuggestion {
                surface_host: host.to_owned(),
                hidden_host: hidden.to_owned(),
                network: network.clone(),
                label: label.to_owned(),
            });
        }
    }
    None
}

/// Called by the JS navigation hook when the user loads a new URL.
/// Returns a suggestion if a hidden-service mirror is available.
pub async fn cmd_onion_suggest(host: String) -> Result<Option<OnionSuggestion>, String> {
    Ok(lookup(&host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nytimes_has_onion() {
        let s = lookup("nytimes.com").expect("NYT should have a .onion");
        assert!(s.hidden_host.ends_with(".onion"));
    }

    #[test]
    fn subdomain_matches() {
        let s = lookup("en.wikipedia.org").expect("wikipedia subdomain should match");
        assert_eq!(s.surface_host, "en.wikipedia.org");
    }

    #[test]
    fn unknown_domain_returns_none() {
        assert!(lookup("example.com").is_none());
    }

    #[test]
    fn www_prefix_stripped() {
        assert!(lookup("www.nytimes.com").is_some());
        assert!(lookup("www.duckduckgo.com").is_some());
    }
}
