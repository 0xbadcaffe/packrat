//! Library crate target — exposes internal modules so integration tests can import them.
#![allow(dead_code)]

pub mod analysis;
#[cfg(feature = "terminal-ui")]
pub mod app;
pub mod capture;
pub mod craft;
pub mod dissector;
pub mod engine;
#[cfg(feature = "terminal-ui")]
pub mod event;
pub mod export;
pub mod filter;
pub mod model;
pub mod net;
pub mod pcap_replay;
pub mod scan;
pub mod sim;
pub mod storage;
#[cfg(feature = "terminal-ui")]
pub mod tabs;
pub mod traceroute;
#[cfg(feature = "terminal-ui")]
pub mod ui;
