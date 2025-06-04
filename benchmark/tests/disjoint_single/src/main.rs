use benchmark::BenchmarkManager;
use crossbeam::channel::{bounded, Receiver, Sender};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use once_cell::sync::OnceCell;
use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::time::Instant;
use std::{sync::Arc, thread};

type TimedTlsData = (Instant, TlsHandshake, ConnRecord);
type TimedDnsData = (Instant, DnsTransaction, ConnRecord);

static TLS_SENDER: OnceCell<Sender<TimedTlsData>> = OnceCell::new();
static DNS_SENDER: OnceCell<Sender<TimedDnsData>> = OnceCell::new();

static BENCHMARK_GLOBAL: OnceCell<Arc<BenchmarkManager>> = OnceCell::new();

fn init_processing_threads<T: std::marker::Send + 'static>(
    sender_cell: &OnceCell<Sender<T>>,
    cores: Vec<usize>,
    thread_fn: fn(Receiver<T>),
    channel_size: usize,
) {
    let (sender, receiver) = bounded::<T>(channel_size);
    sender_cell
        .set(sender)
        .expect("Senders already initialized.");

    for core in cores {
        let receiver_clone = receiver.clone();
        thread::spawn(move || {
            let mut cpu_set = CpuSet::new();

            if cpu_set.set(core).is_ok() {
                if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpu_set) {
                    eprintln!("Failed to set CPU affinity: {}", e);
                }

                thread_fn(receiver_clone);
            }
        });
    }
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    if let Some(sender) = TLS_SENDER.get() {
        match sender.try_send((Instant::now(), tls.clone(), conn_record.clone())) {
            Ok(_) => {
                if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                    benchmark_manager.increment_processed_subscriptions();
                }
            }
            Err(_) => {
                if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                    benchmark_manager.increment_dropped_subscriptions();
                }
            }
        }
    }
}

// Process TLS data in a dedicated thread.
fn tls_processing_thread(receiver: Receiver<TimedTlsData>) {
    for (start_time, _tls, _conn_record) in receiver {
        if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
            benchmark_manager.calculate_latency(start_time);
        }
    }
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
    if let Some(sender) = DNS_SENDER.get() {
        match sender.try_send((Instant::now(), dns.clone(), conn_record.clone())) {
            Ok(_) => {
                if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                    benchmark_manager.increment_processed_subscriptions();
                }
            }

            Err(_) => {
                if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                    benchmark_manager.increment_dropped_subscriptions();
                }
            }
        }
    }
}

// Process DNS data in a dedicated thread.
fn dns_processing_thread(receiver: Receiver<TimedDnsData>) {
    for (start_time, _dns, _conn_record) in receiver {
        if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
            benchmark_manager.calculate_latency(start_time);
        }
    }
}

#[retina_main(2)]
fn main() {
    let benchmark_manager = Arc::new(BenchmarkManager::new());
    
    BENCHMARK_GLOBAL
        .set(benchmark_manager)
        .expect("Already initialized");
    
    init_processing_threads::<TimedTlsData>(&TLS_SENDER, Vec::from([1, 2]), tls_processing_thread, 100000);
    init_processing_threads::<TimedDnsData>(&DNS_SENDER, Vec::from([3]), dns_processing_thread, 100000);
    
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    
    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
        benchmark_manager.print_results();
    }
}
