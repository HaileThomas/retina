use retina_core::{config::load_config, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::{sync::Arc, thread, time::Instant};
use crossbeam::channel::{bounded, select, Sender, Receiver};
use once_cell::sync::OnceCell;
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use clap::Parser; 
use benchmark::BenchmarkManager;

type TimedTlsData = (Instant, TlsHandshake, ConnRecord);
type TimedDnsData = (Instant, DnsTransaction, ConnRecord);

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, default_value = "1000")]
    queue_size: u64,
}

static TLS_SENDER: OnceCell<Sender<TimedTlsData>> = OnceCell::new();
static DNS_SENDER: OnceCell<Sender<TimedDnsData>> = OnceCell::new();
static BENCHMARK_GLOBAL: OnceCell<Arc<BenchmarkManager>> = OnceCell::new();

fn init_processing_threads(cores: Vec<usize>, channel_size: u64) {
    let (tls_sender, tls_receiver) = bounded::<TimedTlsData>(channel_size as usize);
    let (dns_sender, dns_receiver) = bounded::<TimedDnsData>(channel_size as usize);

    TLS_SENDER.set(tls_sender).expect("TLS Sender already initialized.");
    DNS_SENDER.set(dns_sender).expect("DNS Sender already initialized.");

    for core in cores {
        let tls_receiver_clone = tls_receiver.clone();
        let dns_receiver_clone = dns_receiver.clone();

        thread::spawn(move || {
            let mut cpu_set = CpuSet::new();
            if cpu_set.set(core).is_ok() {
                let _ = sched_setaffinity(Pid::from_raw(0), &cpu_set);
            }
            process_subscriptions(tls_receiver_clone, dns_receiver_clone);
        });
    }
}

fn process_subscriptions(
    tls_receiver: Receiver<TimedTlsData>,
    dns_receiver: Receiver<TimedDnsData>
) {
    loop {
        select! {
            recv(tls_receiver) -> msg => {
                if let Ok((start_time, _tls, _conn_record)) = msg {
                    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                        benchmark_manager.calculate_latency(start_time);
                    }
                }
            }
            recv(dns_receiver) -> msg => {
                if let Ok((start_time, _dns, _conn_record)) = msg {
                    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                        benchmark_manager.calculate_latency(start_time);
                    }
                }
            }
        }
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

#[retina_main(2)]
fn main() {
    let args = Args::parse(); 
    let queue_size: u64 = args.queue_size; 

    let benchmark_manager = Arc::new(BenchmarkManager::new(queue_size));
    BENCHMARK_GLOBAL.set(benchmark_manager).expect("Already initialized");

    init_processing_threads(Vec::from([1, 2, 3]), queue_size);

    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
        benchmark_manager.print_results();
    }
}
