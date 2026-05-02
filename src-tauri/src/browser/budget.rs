use serde::{Deserialize, Serialize};

/// Default upper bound on simultaneously open tabs.
pub const DEFAULT_TAB_LIMIT: u32 = 13;

/// Persistent user preference for the maximum number of open tabs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabBudgetConfig {
    /// Hard limit set by the user. Range: 1–50. Default: 13.
    pub max_tabs: u32,
}

impl Default for TabBudgetConfig {
    fn default() -> Self {
        TabBudgetConfig {
            max_tabs: DEFAULT_TAB_LIMIT,
        }
    }
}

impl TabBudgetConfig {
    /// Load from the database key `"tab_limit"`.
    /// Returns the default when the key is absent or unparseable.
    pub fn load(db: &crate::storage::db::Db) -> Self {
        let max_tabs = db
            .get_setting("tab_limit")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_TAB_LIMIT)
            .clamp(1, 50);
        TabBudgetConfig { max_tabs }
    }

    /// Persist the current config to the database.
    pub fn save(&self, db: &crate::storage::db::Db) -> anyhow::Result<()> {
        db.set_setting("tab_limit", &self.max_tabs.to_string())
    }
}

/// A computed snapshot of the current tab budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabBudget {
    /// The active tab limit.
    pub t_max: u32,
    /// True when `current_count + 1 >= t_max` (approaching the limit).
    pub pressure_high: bool,
    /// Seconds before an inactive tab is promoted to shallow sleep.
    /// Shortened when the tab count is high.
    pub sleep_timer_s: u64,
}

impl TabBudget {
    /// Returns `true` when no more tabs may be opened.
    pub fn is_at_limit(&self, current_count: u32) -> bool {
        current_count >= self.t_max
    }
}

/// Derive a [`TabBudget`] from user config and the current open-tab count.
///
/// Sleep-timer schedule:
/// - Below 80 % fill:     10 minutes.
/// - 80 %–100 % fill:     linearly interpolated 10 → 5 minutes.
/// - At or above limit:   5 minutes.
pub fn compute_budget(cfg: &TabBudgetConfig, current_tab_count: u32) -> TabBudget {
    let t_max = cfg.max_tabs.max(1);
    let fill_ratio = current_tab_count as f64 / t_max as f64;

    let sleep_timer_s = if fill_ratio >= 1.0 {
        5 * 60
    } else if fill_ratio >= 0.8 {
        let overage = (fill_ratio - 0.8) / 0.2;
        let range = (10 * 60 - 5 * 60) as f64;
        (10.0 * 60.0 - overage * range) as u64
    } else {
        10 * 60
    };

    TabBudget {
        t_max,
        pressure_high: current_tab_count + 1 >= t_max,
        sleep_timer_s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limit() {
        assert_eq!(TabBudgetConfig::default().max_tabs, DEFAULT_TAB_LIMIT);
    }

    #[test]
    fn respects_config() {
        let cfg = TabBudgetConfig { max_tabs: 7 };
        assert_eq!(compute_budget(&cfg, 4).t_max, 7);
    }

    #[test]
    fn pressure_flag() {
        let cfg = TabBudgetConfig { max_tabs: 5 };
        assert!(compute_budget(&cfg, 5).pressure_high);
        assert!(!compute_budget(&cfg, 3).pressure_high);
    }

    #[test]
    fn sleep_timer_shortens_under_load() {
        let cfg = TabBudgetConfig { max_tabs: 10 };
        let low = compute_budget(&cfg, 2);
        let high = compute_budget(&cfg, 9);
        assert!(high.sleep_timer_s < low.sleep_timer_s);
    }

    #[test]
    fn minimum_limit_clamped_to_one() {
        let b = compute_budget(&TabBudgetConfig { max_tabs: 0 }, 0);
        assert!(b.t_max >= 1);
    }
}
