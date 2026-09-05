//! vitals — live per-process resource monitor with user-defined alerting.
//!
//! Reads `/proc` directly. No dependencies outside the standard library.
//!
//! ```text
//!   /proc  ──> procfs.rs  ──> sample.rs ──> delta.rs ──> rules.rs
//!             (pure parsers) (one scan)   (counters   (sustain +
//!                                          to rates)   hysteresis)
//!                                              |            |
//!                                              v            v
//!                                         sampler.rs (background thread)
//!                                              |
//!                                       Arc<RwLock<Shared>>
//!                                              |
//!                                          bin/vitals.rs (TUI / JSON)
//! ```

pub mod delta;
pub mod procfs;
pub mod ring;
pub mod rules;
pub mod sample;
pub mod sampler;
pub mod units;
