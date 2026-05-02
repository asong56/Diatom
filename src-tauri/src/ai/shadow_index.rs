use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub museum_id: String,
    pub url: String,
    pub title: String,
    pub snippet: String,
    pub score: f32,
    pub frozen_at: i64,
    pub source: SearchSource,
    pub quality_tier: QualityTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchSource {
    LocalMuseum,
    P2pNode { node_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityTier {
    /// Wraps a Museum snapshot (title + URL + snippet).
    HumanCurated,
    /// Optional AI-generated summary of the archived page content.
    AiHighRated,
    /// Passively browsed (not explicitly archived — lower confidence).
    Standard,
}

/// TF-IDF in-memory index built from Museum entries at query time.
pub struct TfIdfIndex {
    /// doc_id → (term → tf)
    term_freq: HashMap<String, HashMap<String, f32>>,
    /// term → df (document frequency)
    doc_freq: HashMap<String, usize>,
    total_docs: usize,
}

impl TfIdfIndex {
    pub fn new() -> Self {
        Self {
            term_freq: HashMap::new(),
            doc_freq: HashMap::new(),
            total_docs: 0,
        }
    }

    pub fn add_document(&mut self, doc_id: &str, text: &str) {
        let tokens = tokenize(text);
        let mut tf: HashMap<String, f32> = HashMap::new();
        for token in &tokens {
            *tf.entry(token.clone()).or_insert(0.0) += 1.0;
        }
        let max_tf = tf.values().cloned().fold(0.0f32, f32::max).max(1.0);
        for v in tf.values_mut() {
            *v /= max_tf;
        }

        for term in tf.keys() {
            *self.doc_freq.entry(term.clone()).or_insert(0) += 1;
        }
        self.term_freq.insert(doc_id.to_owned(), tf);
        self.total_docs += 1;
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<(String, f32)> {
        let query_terms = tokenize(query);
        let n = self.total_docs as f32;

        let mut scores: HashMap<&str, f32> = HashMap::new();
        for term in &query_terms {
            let idf = self
                .doc_freq
                .get(term)
                .map(|&df| (n / (df as f32 + 1.0)).ln() + 1.0)
                .unwrap_or(0.0);
            for (doc_id, tf_map) in &self.term_freq {
                if let Some(&tf) = tf_map.get(term) {
                    *scores.entry(doc_id.as_str()).or_insert(0.0) += tf * idf;
                }
            }
        }

        let mut ranked: Vec<(String, f32)> = scores
            .into_iter()
            .map(|(id, s)| (id.to_owned(), s))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked.truncate(limit);
        ranked
    }
}

fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 2)
        .map(|t| t.to_lowercase())
        .collect()
}

/// Generate an anonymous keyword hash for P2P queries (prevents cross-query correlation).
pub fn anonymize_keyword(keyword: &str, session_salt: &[u8; 32]) -> String {
    let mut input = session_salt.to_vec();
    input.extend_from_slice(keyword.to_lowercase().as_bytes());
    hex::encode(blake3::hash(&input).as_bytes())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiasContrastResult {
    pub current_url: String,
    pub current_title: String,
    pub related_perspectives: Vec<PerspectiveEntry>,
    pub mermaid_divergence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerspectiveEntry {
    pub museum_id: String,
    pub url: String,
    pub title: String,
    pub snippet: String,
    pub estimated_lean: PoliticalLean,
    pub similarity_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoliticalLean {
    Left,
    CenterLeft,
    Center,
    CenterRight,
    Right,
    Unknown,
}

/// P2P search (Nostr-based). Returns Err if P2P mode is not enabled.
pub fn estimate_lean(domain: &str) -> PoliticalLean {
    let d = domain.to_lowercase();
    if ["theguardian.com", "huffpost.com", "vox.com", "msnbc.com"]
        .iter()
        .any(|s| d.contains(s))
    {
        PoliticalLean::Left
    } else if ["bbc.com", "reuters.com", "apnews.com", "nytimes.com"]
        .iter()
        .any(|s| d.contains(s))
    {
        PoliticalLean::Center
    } else if ["wsj.com", "economist.com", "ft.com"]
        .iter()
        .any(|s| d.contains(s))
    {
        PoliticalLean::CenterRight
    } else if ["foxnews.com", "breitbart.com", "dailywire.com"]
        .iter()
        .any(|s| d.contains(s))
    {
        PoliticalLean::Right
    } else {
        PoliticalLean::Unknown
    }
}

/// Generate a Mermaid chart for the bias comparison view
pub fn generate_mermaid_divergence(topic: &str, perspectives: &[PerspectiveEntry]) -> String {
    let mut mermaid = format!("graph TD\n    T[\"🗞 {topic}\"]\n");
    for (i, p) in perspectives.iter().take(3).enumerate() {
        let lean_icon = match p.estimated_lean {
            PoliticalLean::Left | PoliticalLean::CenterLeft => "◀",
            PoliticalLean::Right | PoliticalLean::CenterRight => "▶",
            _ => "●",
        };
        let title_short: String = p.title.chars().take(40).collect();
        let _ = write!(mermaid, "    T --> P{i}[\"{lean_icon} {title_short}\"]\n");
    }
    mermaid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tfidf_basic_search() {
        let mut idx = TfIdfIndex::new();
        idx.add_document("doc1", "Rust memory safety ownership borrowing");
        idx.add_document("doc2", "Python machine learning deep neural network");
        idx.add_document("doc3", "Rust async tokio performance");

        let results = idx.search("Rust performance", 3);
        assert!(!results.is_empty());
        let rust_docs: Vec<_> = results
            .iter()
            .filter(|(id, _)| id.starts_with("doc1") || id.starts_with("doc3"))
            .collect();
        assert!(!rust_docs.is_empty());
    }

    #[test]
    fn anonymize_keyword_different_salts() {
        let salt1: [u8; 32] = rand::random();
        let salt2: [u8; 32] = rand::random();
        let h1 = anonymize_keyword("rust", &salt1);
        let h2 = anonymize_keyword("rust", &salt2);
        assert_ne!(h1, h2, "Different salts must produce different hashes");
    }
}
