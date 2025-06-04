use retina_core::{config::default_config, config::load_config, Runtime, CoreId};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use crossbeam::channel::{bounded, Sender, Receiver, Select};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use std::{thread, sync::OnceLock, collections::HashMap};

type TlsData = (TlsHandshake, ConnRecord);
type DnsData = (DnsTransaction, ConnRecord);

static TLS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<TlsData>, Receiver<TlsData>)>> = OnceLock::new();
static DNS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<DnsData>, Receiver<DnsData>)>> = OnceLock::new();

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
                } else {
                    println!("Thread pinned to core {}.", core);
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
            if let Err(e) = sender.try_send((tls.clone(), conn_record.clone())) {
                eprintln!("Failed to send TLS data through channel: {}", e);
            } 
        } else {
            eprintln!("No TLS sender for Core ID: {}", rx_core);
        }
    } else {
        eprintln!("TLS sender not initialized");
    }
}

fn tls_processing_thread(receivers: &Vec<Receiver<TlsData>>) {
    println!("TLS processing thread started!");

    let mut select = Select::new();
    for receiver in receivers {
        select.recv(receiver);
    }

    loop {
        let oper = select.select();
        let index = oper.index();

        match oper.recv(&receivers[index]) {
            Ok((tls, conn_record)) => {
                println!("TLS SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
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
            if let Err(e) = sender.try_send((dns.clone(), conn_record.clone())) {
                eprintln!("Failed to send DNS data through channel: {}", e);
            }
        } else {
            eprintln!("No DNS sender for Core ID: {}", rx_core);
        }
    } else {
        eprintln!("DNS sender not initialized.");
    }
}

fn dns_processing_thread(receivers: &Vec<Receiver<DnsData>>) {
    println!("DNS processing thread started!");

    let mut select = Select::new();
    for receiver in receivers {
        select.recv(receiver);
    }

    loop {
        let oper = select.select();
        let index = oper.index();

        match oper.recv(&receivers[index]) {
            Ok((dns, conn_record)) => {
                println!(
                    "DNS query domain: {}, conn. metrics: {:?}",
                    dns.query_domain(),
                    conn_record
                );
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
    let tls_processing_cores = vec![1, 2];
    let dns_processing_cores = vec![3]; 

    let config = load_config("./configs/offline.toml");
    let rx_cores = config.get_all_rx_core_ids();
    println!("available rx_cores: {:?}", rx_cores);  

    let tls_channel_size = 100_000;
    let dns_channel_size = 100_000;

    spawn_processing_threads::<TlsData>(
        &TLS_CHANNELS,
        tls_processing_cores,
        rx_cores.clone(),
        tls_processing_thread,
        tls_channel_size,
    );

    spawn_processing_threads::<DnsData>(
        &DNS_CHANNELS,
        dns_processing_cores,
        rx_cores.clone(),
        dns_processing_thread,
        dns_channel_size,
    );

    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
