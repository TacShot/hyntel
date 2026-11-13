//! hyntel-core: Cross-platform security audit engine

pub mod models;
pub mod command_runner;
pub mod platform;
pub mod checks;
pub mod nvd;
pub mod inventory;
pub mod remediation;
pub mod reporting;
pub mod audit;
pub mod logs;
pub mod ad;

pub use models::*;
pub use audit::AuditEngine;