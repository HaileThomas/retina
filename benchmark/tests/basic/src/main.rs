use retina_core::{config::load_config, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use benchmark::BenchmarkManager;
use std::{sync::Arc, time::Instant};
use once_cell::sync::OnceCell;

static BENCHMARK_GLOBAL: OnceCell<Arc<BenchmarkManager>> = OnceCell::new();

#[filter("tls")]
fn tls_cb(_tls: &TlsHandshake, _conn_record: &ConnRecord) {
    let start_time = Instant::now();
        
    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
        benchmark_manager.increment_processed_subscriptions();
        benchmark_manager.calculate_latency(start_time);
    }
}

#[filter("dns")]
fn dns_cb(_dns: &DnsTransaction, _conn_record: &ConnRecord) {
    let start_time = Instant::now();

    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
        benchmark_manager.increment_processed_subscriptions();
        benchmark_manager.calculate_latency(start_time);
    }
}

#[retina_main(2)]
fn main() {
    let benchmark_manager = Arc::new(BenchmarkManager::new(0 as u64));
    BENCHMARK_GLOBAL.set(benchmark_manager).expect("Already initialized");
    
    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    
    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
        benchmark_manager.print_results();
    }
}



