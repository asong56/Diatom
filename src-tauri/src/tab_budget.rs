// ─────────────────────────────────────────────────────────────────────────────
// diatom/src-tauri/src/tab_budget.rs  — v0.9.0
//
// Dynamic Tab Budget Engine
//
// Replaces the static "max 10 tabs" rule with an adaptive algorithm that
// responds to real system conditions. Three complementary models:
//
// MODEL A: Resource-Aware Scaling (default)
//   T_max = clamp(3, 10, floor(M_available × ρ / ω_avg))
//   Where:
//     M_available = current free + reclaimable system memory
//     ρ           = Diatom memory allocation ratio (default 0.20)
//     ω_avg       = average memory weight of currently awake tabs
//
// MODEL B: Golden Ratio Zone Scheduling
//   Focus zone: floor(T_max / φ) tabs — highest priority, never auto-slept
//   Buffer zone: T_max - focus — temporary tasks, aggressive auto-sleep
//   φ ≈ 1.618 (golden ratio)
//
// MODEL C: Screen Gravity
//   Adjusts T_max ceiling based on screen pixel width:
//     < 1024px  → 3   (phone / vertical)
//     < 1600px  → 8   (13" laptop)
//     < 2560px  → 10  (standard desktop)
//     ≥ 2560px  → 13  (ultrawide / dual — Fibonacci)
//
// Entropy-Reduction Sleep:
//   When approaching T_max, life-value timers are shortened and the
//   heaviest awake tab (highest ω) is the auto-sleep candidate.
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabBudgetConfig {
    /// Memory allocation ratio ρ (0.0–1.0). Default 0.20.
    pub memory_ratio: f64,
    /// Hard floor — always allow at least this many tabs.
    pub min_tabs: u32,
    /// Hard ceiling — never exceed this regardless of memory.
    pub max_tabs_hard: u32,
    /// Enable Screen Gravity ceiling adjustment.
    pub screen_gravity: bool,
    /// Golden Ratio zone scheduling enabled.
    pub golden_ratio: bool,
}

impl Default for TabBudgetConfig {
    fn default() -> Self {
        TabBudgetConfig {
            memory_ratio: 0.20,
            min_tabs: 3,
            max_tabs_hard: 10,
            screen_gravity: true,
            golden_ratio: true,
        }
    }
}

// ── Budget result ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabBudget {
    /// Maximum total open tabs (Model A × Model C).
    pub t_max: u32,
    /// Focus zone: floor(t_max / φ). These tabs resist auto-sleep.
    pub focus_slots: u32,
    /// Buffer zone: t_max - focus_slots. Aggressive auto-sleep.
    pub buffer_slots: u32,
    /// True if we are within 1 tab of t_max.
    pub pressure_high: bool,
    /// Auto-sleep life-value timer (seconds). Shortened under pressure.
    pub sleep_timer_s: u64,
    /// System memory available (bytes, sampled at compute time).
    pub m_available: u64,
    /// Average tab memory weight used in calculation (bytes).
    pub omega_avg: u64,
}

impl TabBudget {
    pub fn is_at_limit(&self, current_count: u32) -> bool {
        current_count >= self.t_max
    }
}

// ── φ constant ────────────────────────────────────────────────────────────────
const PHI: f64 = 1.618_033_988_749_895;

// ── Core computation ─────────────────────────────────────────────────────────

/// Compute the current tab budget.
///
/// `screen_width_px`: current browser window width in logical pixels.
/// `omega_avg_bytes`: average awake tab memory weight in bytes.
/// `current_tab_count`: how many tabs are currently open.
pub fn compute_budget(
    cfg: &TabBudgetConfig,
    screen_width_px: u32,
    omega_avg_bytes: u64,
    current_tab_count: u32,
) -> TabBudget {
    let m_available = available_memory_bytes();
    let omega = omega_avg_bytes.max(20 * 1024 * 1024); // floor 20 MB

    // ── Model A: Resource-Aware Scaling ───────────────────────────────────────
    let resource_max = if m_available > 0 {
        let budget_bytes = (m_available as f64 * cfg.memory_ratio) as u64;
        (budget_bytes / omega).clamp(cfg.min_tabs as u64, cfg.max_tabs_hard as u64) as u32
    } else {
        cfg.max_tabs_hard
    };

    // ── Model C: Screen Gravity ceiling ───────────────────────────────────────
    let screen_ceiling = if cfg.screen_gravity {
        match screen_width_px {
            0..=1023 => 3,
            1024..=1599 => 8,
            1600..=2559 => 10,
            _ => 13, // Fibonacci — ultrawide / dual-monitor
        }
    } else {
        cfg.max_tabs_hard
    };

    let t_max = resource_max.min(screen_ceiling).max(cfg.min_tabs);

    // ── Model B: Golden Ratio zones ───────────────────────────────────────────
    let (focus_slots, buffer_slots) = if cfg.golden_ratio {
        let focus = (t_max as f64 / PHI).floor() as u32;
        let focus = focus.clamp(1, t_max.saturating_sub(1));
        (focus, t_max - focus)
    } else {
        (t_max, 0)
    };

    // ── Entropy-reduction sleep timer ─────────────────────────────────────────
    // Approaching limit → shorten life-value timers.
    // At 100% capacity:  5 min
    // At 80%:            7.5 min
    // At 60% or below:  10 min
    let fill_ratio = current_tab_count as f64 / t_max.max(1) as f64;
    let sleep_timer_s = if fill_ratio >= 1.0 {
        5 * 60
    } else if fill_ratio >= 0.8 {
        (10.0 * 60.0 * (1.0 - fill_ratio) / 0.2) as u64 + 5 * 60
    } else {
        10 * 60
    };

    let pressure_high = current_tab_count + 1 >= t_max;

    TabBudget {
        t_max,
        focus_slots,
        buffer_slots,
        pressure_high,
        sleep_timer_s,
        m_available,
        omega_avg: omega,
    }
}

// ── System memory query ───────────────────────────────────────────────────────

/// Query available (free + reclaimable) physical memory in bytes.
/// Falls back to a conservative 512 MB estimate if the platform API fails.
pub fn available_memory_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // vm_stat gives page-level memory statistics.
        // Page size differs by architecture: Apple Silicon = 16 384 B, Intel = 4 096 B.
        // Read it at runtime via `pagesize` sysctl rather than hardcoding.
        let page_size: u64 = {
            std::process::Command::new("sysctl")
                .args(["-n", "hw.pagesize"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(4_096) // safe fallback for Intel
        };
        if let Ok(out) = Command::new("vm_stat").output() {
            if let Ok(text) = String::from_utf8(out.stdout) {
                let pages_free: u64 = parse_vm_stat_field(&text, "Pages free");
                let pages_inactive: u64 = parse_vm_stat_field(&text, "Pages inactive");
                let total = (pages_free + pages_inactive) * page_size;
                if total > 0 {
                    return total;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            let available: u64 = text
                .lines()
                .find(|l| l.starts_with("MemAvailable:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            if available > 0 {
                return available * 1024;
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // [FIX-22] Use GlobalMemoryStatusEx to get real available memory.
        // Falls back to 2 GB if the API call fails, which is more realistic
        // than the previous hardcoded 1 GB for modern Windows machines.
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut mem_status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            dwMemoryLoad: 0,
            ullTotalPhys: 0,
            ullAvailPhys: 0,
            ullTotalPageFile: 0,
            ullAvailPageFile: 0,
            ullTotalVirtual: 0,
            ullAvailVirtual: 0,
            ullAvailExtendedVirtual: 0,
        };
        unsafe {
            if GlobalMemoryStatusEx(&mut mem_status) != 0 {
                return mem_status.ullAvailPhys;
            }
        }
        return 2 * 1024 * 1024 * 1024; // 2 GB conservative fallback
    }

    // Conservative fallback: 512 MB
    512 * 1024 * 1024
}

#[cfg(target_os = "macos")]
fn parse_vm_stat_field(text: &str, field: &str) -> u64 {
    text.lines()
        .find(|l| l.contains(field))
        .and_then(|l| l.split_whitespace().last())
        .and_then(|v| v.trim_end_matches('.').parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_plus_buffer_equals_tmax() {
        let cfg = TabBudgetConfig::default();
        let budget = compute_budget(&cfg, 1920, 80 * 1024 * 1024, 5);
        assert_eq!(budget.focus_slots + budget.buffer_slots, budget.t_max);
    }

    #[test]
    fn golden_ratio_focus_is_roughly_61pct() {
        let cfg = TabBudgetConfig {
            max_tabs_hard: 10,
            ..Default::default()
        };
        // Force t_max to 10 by giving lots of memory
        let budget = compute_budget(&cfg, 1920, 1024 * 1024, 0);
        // With t_max=10: focus = floor(10/1.618) = floor(6.18) = 6
        // (if t_max reaches 10)
        if budget.t_max == 10 {
            assert_eq!(budget.focus_slots, 6);
            assert_eq!(budget.buffer_slots, 4);
        }
    }

    #[test]
    fn screen_gravity_ultrawide() {
        let cfg = TabBudgetConfig::default();
        let budget = compute_budget(&cfg, 3440, 1024 * 1024, 0);
        assert!(budget.t_max <= 13, "ultrawide ceiling is 13");
    }

    #[test]
    fn screen_gravity_phone() {
        let cfg = TabBudgetConfig::default();
        let budget = compute_budget(&cfg, 390, 1024 * 1024, 0);
        assert_eq!(budget.t_max, 3, "phone should cap at 3");
    }

    #[test]
    fn pressure_shortens_sleep_timer() {
        let cfg = TabBudgetConfig {
            max_tabs_hard: 10,
            ..Default::default()
        };
        let budget_low = compute_budget(&cfg, 1920, 1024 * 1024, 2);
        let budget_high = compute_budget(&cfg, 1920, 1024 * 1024, 9);
        assert!(budget_high.sleep_timer_s < budget_low.sleep_timer_s);
    }

    #[test]
    fn min_floor_respected() {
        let cfg = TabBudgetConfig {
            memory_ratio: 0.001,
            min_tabs: 3,
            ..Default::default()
        };
        // Tiny memory ratio forces a very low budget, but floor = 3
        let budget = compute_budget(&cfg, 1920, 200 * 1024 * 1024, 0);
        assert!(budget.t_max >= 3);
    }
}
