pub mod consts;
pub mod types;

#[cfg(not(target_arch = "wasm32"))]
pub mod scanner;

pub mod util;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(not(target_arch = "wasm32"))]
use once_cell::sync::Lazy;
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;

#[cfg(not(target_arch = "wasm32"))]
static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

#[cfg(not(target_arch = "wasm32"))]
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RUNTIME.block_on(fut)
}

#[cfg(target_arch = "wasm32")]
pub fn block_on<F: std::future::Future>(_fut: F) -> F::Output {
    panic!("block_on not supported on wasm32")
}