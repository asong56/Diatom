//! Price comparison research module.
//!
//! # Status: Labs / Research
//!
//! This module provides the data types, price-extraction script, and local
//! computation logic for the P2P Price Comparison feature.
//!
//! **Dependency not yet implemented:** for live peer prices this feature
//! requires a P2P data aggregation layer (peer discovery, encrypted gossip,
//! privacy-preserving aggregation). Until that layer exists only the local
//! price-extraction and alert-computation logic is functional.
//!
//! The feature is gated behind the `"lab_price_comparison"` Labs flag. It
//! must not make any external network calls without explicit user opt-in and
//! without a fully audited privacy-preserving transport.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceSignal {
    pub url: String,
    /// URL hash — de-parameterised canonical form + ASIN/SKU hash.
    pub canonical_product_id: String,
    pub detected_price: Option<f64>,
    pub currency: Option<String>,
    pub detected_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceComparisonResult {
    pub product_id: String,
    pub your_price: f64,
    pub currency: String,
    pub peer_prices: Vec<PeerPrice>,
    pub network_avg: f64,
    pub network_min: f64,
    /// Percentage deviation from network average. Positive = you pay more.
    pub deviation_pct: f32,
    pub alert_level: PriceAlertLevel,
    pub suggestion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPrice {
    pub price: f64,
    pub reported_at: i64,
    /// Number of peers contributing to this aggregated data point.
    pub node_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceAlertLevel {
    /// Prices match within ±3% — no significant deviation.
    Normal,
    /// Price deviation 3–10% — mild concern.
    Elevated,
    /// Price deviation 10–20% — likely dynamic pricing.
    High,
    /// Price deviation >20% — strong evidence of discriminatory pricing.
    Severe,
}

/// Derive a stable product identifier from a URL.
///
/// Strips query parameters and fragments, then hashes the canonical form with
/// BLAKE3. Returns the first 16 hex characters.
pub fn canonical_product_id(url: &str) -> String {
    let normalized = url::Url::parse(url)
        .map(|mut u| {
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        })
        .unwrap_or_else(|_| url.to_owned());
    hex::encode(blake3::hash(normalized.as_bytes()).as_bytes())[..16].to_owned()
}

/// Calculate alert level from the deviation between `your_price` and
/// `network_avg`.
pub fn compute_alert(your_price: f64, network_avg: f64) -> PriceAlertLevel {
    if network_avg <= 0.0 {
        return PriceAlertLevel::Normal;
    }
    let deviation = (your_price - network_avg) / network_avg * 100.0;
    match deviation as i32 {
        d if d <= 3 => PriceAlertLevel::Normal,
        d if d <= 10 => PriceAlertLevel::Elevated,
        d if d <= 20 => PriceAlertLevel::High,
        _ => PriceAlertLevel::Severe,
    }
}

/// Generate a human-readable recommendation based on the alert level.
pub fn generate_suggestion(alert: &PriceAlertLevel, deviation_pct: f32) -> String {
    match alert {
        PriceAlertLevel::Normal => {
            format!("Prices match within {deviation_pct:.1}% — no significant deviation detected.")
        }
        PriceAlertLevel::Elevated => format!(
            "⚠️ Price deviation {deviation_pct:.1}%. You may be seeing mild dynamic pricing."
        ),
        PriceAlertLevel::High => format!(
            "⚠️ Price deviation {deviation_pct:.1}%. Dynamic pricing likely. Consider using a shadow-fingerprint IP."
        ),
        PriceAlertLevel::Severe => format!(
            "🚨 Strong price discrimination detected ({deviation_pct:.1}% deviation). Strongly recommend rotating IP and clearing cookies."
        ),
    }
}

/// JavaScript injected into product pages to extract the displayed price.
///
/// Attempts JSON-LD → Open Graph meta → site-specific CSS selectors in order.
/// On success it sets `window.__diatom_price` and fires a
/// `diatom:price-detected` CustomEvent.
pub const PRICE_EXTRACTOR_SCRIPT: &str = r#"
(function() {
  function extractPrice() {
    for (const script of document.querySelectorAll('script[type="application/ld+json"]')) {
      try {
        const data = JSON.parse(script.textContent);
        const offers = data.offers || (data['@graph'] || []).flatMap(g => g.offers || []);
        const offer = Array.isArray(offers) ? offers[0] : offers;
        if (offer && offer.price) {
          return { price: parseFloat(offer.price), currency: offer.priceCurrency || 'USD', source: 'json-ld' };
        }
      } catch(e) {}
    }

    const metaPrice = document.querySelector(
      'meta[property="product:price:amount"], meta[itemprop="price"]'
    );
    if (metaPrice) {
      const currency =
        document.querySelector('meta[property="product:price:currency"]')?.content || 'USD';
      return { price: parseFloat(metaPrice.content), currency, source: 'meta' };
    }

    const selectors = [
      '.a-price .a-offscreen',             // Amazon
      '#priceblock_ourprice', '#priceblock_dealprice',
      '.price-box .price', '[itemprop="price"]',
      '.J-price strong', '.price-num',     // JD / Taobao
      '[data-testid="price-and-discount"] .prco-text',  // Booking
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el) {
        const text = el.textContent.replace(/[^\d.,]/g, '');
        const price = parseFloat(text.replace(',', '.'));
        if (!isNaN(price) && price > 0) {
          return { price, currency: 'USD', source: 'selector', selector: sel };
        }
      }
    }
    return null;
  }

  const result = extractPrice();
  if (result) {
    window.__diatom_price = result;
    window.dispatchEvent(new CustomEvent('diatom:price-detected', { detail: result }));
  }
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_id_strips_params() {
        let id1 = canonical_product_id("https://amazon.com/dp/B08N5WRWNW?ref=foo&tag=bar");
        let id2 = canonical_product_id("https://amazon.com/dp/B08N5WRWNW?ref=other");
        assert_eq!(
            id1, id2,
            "Same product URL with different params should yield same ID"
        );
    }

    #[test]
    fn alert_level_computation() {
        assert!(matches!(
            compute_alert(100.0, 100.0),
            PriceAlertLevel::Normal
        ));
        assert!(matches!(compute_alert(120.0, 100.0), PriceAlertLevel::High));
        assert!(matches!(
            compute_alert(150.0, 100.0),
            PriceAlertLevel::Severe
        ));
    }
}
