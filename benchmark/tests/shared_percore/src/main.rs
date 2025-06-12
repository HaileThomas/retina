use retina_core::{config::default_config, config::load_config, Runtime, CoreId};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::{thread, collections::HashMap, sync::Arc, time::Instant};
use crossbeam::channel::{bounded, select, Sender, Receiver};
use std::sync::OnceLock;
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

static TLS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<TimedTlsData>, Receiver<TimedTlsData>)>> = OnceLock::new();
static DNS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<TimedDnsData>, Receiver<TimedDnsData>)>> = OnceLock::new();
static BENCHMARK_GLOBAL: OnceLock<Arc<BenchmarkManager>> = OnceLock::new();

fn init_processing_threads(processing_cores: Vec<usize>, rx_cores: Vec<CoreId>, channel_size: u64) {
    let mut tls_channels_map = HashMap::new();
    let mut dns_channels_map = HashMap::new();
    
    for core in &rx_cores {
        let (tls_sender, tls_receiver) = bounded::<TimedTlsData>(channel_size as usize);
        let (dns_sender, dns_receiver) = bounded::<TimedDnsData>(channel_size as usize);
        tls_channels_map.insert(*core, (tls_sender, tls_receiver));
        dns_channels_map.insert(*core, (dns_sender, dns_receiver));
    }
    
    TLS_CHANNELS.set(tls_channels_map).expect("TLS Channels already initialized.");
    DNS_CHANNELS.set(dns_channels_map).expect("DNS Channels already initialized.");
    
    let tls_receivers: Vec<Receiver<TimedTlsData>> = TLS_CHANNELS
        .get()
        .expect("TLS Channels must be initialized")
        .values()
        .map(|(_, rx)| rx.clone())
        .collect();
        
    let dns_receivers: Vec<Receiver<TimedDnsData>> = DNS_CHANNELS
        .get()
        .expect("DNS Channels must be initialized")
        .values()
        .map(|(_, rx)| rx.clone())
        .collect();
    
    for core in processing_cores {
        let tls_receivers_clone = tls_receivers.clone();
        let dns_receivers_clone = dns_receivers.clone();
        
        thread::spawn(move || {
            let mut cpu_set = CpuSet::new();
            if cpu_set.set(core).is_ok() {
                let _ = sched_setaffinity(Pid::from_raw(0), &cpu_set);
            }
            process_subscriptions(tls_receivers_clone, dns_receivers_clone);
        });
    }
}

fn process_subscriptions(
    tls_receivers: Vec<Receiver<TimedTlsData>>,
    dns_receivers: Vec<Receiver<TimedDnsData>>
) {
    loop {
        select! {
            recv(tls_receivers.iter().next().unwrap()) -> msg => {
                if let Ok((start_time, _tls, _conn_record)) = msg {
                    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                        benchmark_manager.calculate_latency(start_time);
                    }
                }
            }
            recv(dns_receivers.iter().next().unwrap()) -> msg => {
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
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord, rx_core: &CoreId) {
    if let Some(channel_map) = TLS_CHANNELS.get() {
        if let Some((sender, _)) = channel_map.get(rx_core) {
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
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord, rx_core: &CoreId) {
    if let Some(channel_map) = DNS_CHANNELS.get() {
        if let Some((sender, _)) = channel_map.get(rx_core) {
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
}

#[retina_main(2)]
fn main() {
    let args = Args::parse(); 
    let queue_size: u64 = args.queue_size; 

    let benchmark_manager = Arc::new(BenchmarkManager::new(queue_size));
    BENCHMARK_GLOBAL.set(benchmark_manager).expect("Already initialized");
    
    let config = load_config("./configs/offline.toml");
    let rx_cores = config.get_all_rx_core_ids();
    
    init_processing_threads(Vec::from([1, 2, 3]), rx_cores, queue_size);
    
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    
    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
        benchmark_manager.print_results();
    }
}
