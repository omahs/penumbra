//! Source code for the Penumbra node software.
#![allow(clippy::clone_on_copy)]

pub mod auto_https;
mod consensus;
mod info;
mod mempool;
mod metrics;
mod request_ext;
mod snapshot;
mod tendermint_proxy;

pub mod testnet;

use request_ext::RequestExt;

pub use crate::metrics::register_metrics;
pub use consensus::Consensus;
pub use info::Info;
pub use mempool::Mempool;
pub use penumbra_component::app::App;
pub use snapshot::Snapshot;
pub use tendermint_proxy::TendermintProxy;
