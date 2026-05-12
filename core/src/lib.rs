use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RUNTIME.block_on(fut)
}

pub mod consts;
pub mod types;
pub mod scanner;
pub mod util;