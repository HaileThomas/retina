use retina_core::{config::default_config, config::load_config, Runtime, CoreId};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use crossbeam::channel::{bounded, Sender, Receiver, Select};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use std::{thread, sync::OnceLock, collections::HashMap, time::Instant};
use std::sync::Arc;
use benchmark::BenchmarkManager; 

type TimedTlsData = (Instant, TlsHandshake, ConnRecord);
type TimedDnsData = (Instant, DnsTransaction, ConnRecord);

static TLS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<TimedTlsData>, Receiver<TimedTlsData>)>> = OnceLock::new();
static DNS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<TimedDnsData>, Receiver<TimedDnsData>)>> = OnceLock::new();
static BENCHMARK_GLOBAL: OnceLock<Arc<BenchmarkManager>> = OnceLock::new(); 

fn spawn_processing_threads<T: std::marker::Send + 'static>(
    channel_cell: &OnceLock<HashMap<CoreId, (Sender<T>, Receiver<T>)>>,
    processing_cores: Vec<usize>,
    rx_cores: Vec<CoreId>,
    thread_fn: fn(&Vec<Receiver<T>>),
    channel_size: usize,
) {
    let mut channels_map = HashMap::new();

    for core in &rx_cores {
        let (sender, receiver) = bounded(channel_size);
        channels_map.insert(*core, (sender, receiver));
    }

    channel_cell.set(channels_map).expect("Channels already set");

    let receivers: Vec<Receiver<T>> = channel_cell
        .get()
        .expect("Channels must be initialized")
        .values()
        .map(|(_, rx)| rx.clone())
        .collect();

    for core in processing_cores {
        let receivers_clone = receivers.clone();

        thread::spawn(move || {
            let mut cpu_set = CpuSet::new();
            if cpu_set.set(core).is_ok() {
                if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpu_set) {
                    eprintln!("Failed to set CPU affinity: {}", e);
                }
            }

            thread_fn(&receivers_clone);
        });
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

fn tls_processing_thread(receivers: &Vec<Receiver<TimedTlsData>>) {
    let mut select = Select::new();
    for receiver in receivers {
        select.recv(receiver);
    }

    loop {
        let oper = select.select();
        let index = oper.index();

        match oper.recv(&receivers[index]) {
            Ok((start_time, _tls, _conn_record)) => {
                if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                    benchmark_manager.calculate_latency(start_time);
                }
            }

            Err(_) => {
                eprintln!("Receiver {} disconnected, exiting thread.", index);
                break;
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

fn dns_processing_thread(receivers: &Vec<Receiver<TimedDnsData>>) {
    let mut select = Select::new();
    for receiver in receivers {
        select.recv(receiver);
    }

    loop {
        let oper = select.select();
        let index = oper.index();

        match oper.recv(&receivers[index]) {
            Ok((start_time, _dns, _conn_record)) => {
                if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
                    benchmark_manager.calculate_latency(start_time);
                }
            }

            Err(_) => {
                eprintln!("Receiver {} disconnected, exiting thread.", index);
                break;
            }
        }
    }
}

#[retina_main(2)]
fn main() {
    let benchmark_manager = Arc::new(BenchmarkManager::new()); 
    BENCHMARK_GLOBAL.set(benchmark_manager).expect("Already initialized"); 

    let config = load_config("./configs/offline.toml");
    let rx_cores = config.get_all_rx_core_ids();  

    spawn_processing_threads::<TimedTlsData>(&TLS_CHANNELS, Vec::from([1, 2]), rx_cores.clone(), tls_processing_thread, 100000);
    spawn_processing_threads::<TimedDnsData>(&DNS_CHANNELS, Vec::from([3]), rx_cores.clone(), dns_processing_thread, 100000); 

    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    if let Some(benchmark_manager) = BENCHMARK_GLOBAL.get() {
        benchmark_manager.print_results(); 
    }
}
