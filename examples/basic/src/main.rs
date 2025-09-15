use clap::{Parser};
use retina_core::{config::load_config, Runtime, rte_rdtsc};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::sync::atomic::{AtomicU64, Ordering};

static SPIN_CYCLES: AtomicU64 = AtomicU64::new(100000);

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, value_name = "CYCLES", default_value = "100000")]
    spin: u64,
}

#[inline]
fn spin(cycles: u64) {
    if cycles == 0 {
        return;
    }
    let start = unsafe { rte_rdtsc() };
    loop {
        let now = unsafe { rte_rdtsc() };
        if now - start > cycles {
            break;
        }
    }
}

#[filter("tls")]
fn tls_cb(_tls: &TlsHandshake, _conn_record: &ConnRecord) {
    let cycles = SPIN_CYCLES.load(Ordering::Relaxed);
    spin(cycles); 
}

#[filter("dns")]
fn dns_cb(_dns: &DnsTransaction, _conn_record: &ConnRecord) {
    let cycles = SPIN_CYCLES.load(Ordering::Relaxed);
    spin(cycles); 
}

#[retina_main(2)]
fn main() {
    let args = Args::parse();
    SPIN_CYCLES.store(args.spin, Ordering::Relaxed);

    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
