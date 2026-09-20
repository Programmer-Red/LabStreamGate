//! LabStreamGate core transport library.
//!
//! A simple crate that proxies pure TCP connections to WebSocket connections
//! and vice versa.

pub mod proxy;

#[cfg(feature = "client")]
pub mod utils;

#[cfg(feature = "client")]
pub mod tunnel;

pub use proxy::{
    Error, Message, ProxyStats, TrafficDirection, TrafficObserver, WrappedWsStream, proxy,
    proxy_observed,
};
