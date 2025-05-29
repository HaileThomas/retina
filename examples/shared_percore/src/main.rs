use retina_core::{config::default_config, Runtime, CoreId};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::{thread, collections::HashMap};
use crossbeam::channel::{bounded, select, Sender, Receiver};
use std::sync::OnceLock;
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;

type TlsData = (TlsHandshake, ConnRecord);
type DnsData = (DnsTransaction, ConnRecord);
 
static TLS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<TlsData>, Receiver<TlsData>)>> = OnceLock::new();
static DNS_CHANNELS: OnceLock<HashMap<CoreId, (Sender<DnsData>, Receiver<DnsData>)>> = OnceLock::new();

fn init_processing_threads(processing_cores: Vec<usize>, rx_cores: Vec<usize>, channel_size: usize){
    let mut tls_channels_map = HashMap::new();
    let mut dns_channels_map = HashMap::new();
    
    for core in &rx_cores {
        let (tls_sender, tls_receiver) = bounded::<TlsData>(channel_size);
        let (dns_sender, dns_receiver) = bounded::<DnsData>(channel_size);
        tls_channels_map.insert(CoreId(*core as u32), (tls_sender, tls_receiver));
        dns_channels_map.insert(CoreId(*core as u32), (dns_sender, dns_receiver));
    }
    
    TLS_CHANNELS.set(tls_channels_map).expect("TLS Channels already initialized.");
    DNS_CHANNELS.set(dns_channels_map).expect("DNS Channels already initialized.");
    
    let tls_receivers: Vec<Receiver<TlsData>> = TLS_CHANNELS
        .get()
        .expect("TLS Channels must be initialized")
        .values()
        .map(|(_, rx)| rx.clone())
        .collect();
        
    let dns_receivers: Vec<Receiver<DnsData>> = DNS_CHANNELS
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
                if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpu_set) {
                    eprintln!("Failed to set CPU affinity: {}", e);
                } else {
                    println!("Thread pinned to core {}.", core);
                }
            }
            process_subscriptions(tls_receivers_clone, dns_receivers_clone);
        });
    }
}

fn process_subscriptions(
    tls_receivers: Vec<Receiver<TlsData>>,
    dns_receivers: Vec<Receiver<DnsData>>
) {
    loop {
        select! {
            recv(tls_receivers.iter().next().unwrap()) -> msg => {
                match msg {
                    Ok((tls, conn_record)) => tls_processing_thread(&tls, &conn_record),
                    Err(e) => eprintln!("TLS channel error: {}", e),
                }
            }
            recv(dns_receivers.iter().next().unwrap()) -> msg => {
                match msg {
                    Ok((dns, conn_record)) => dns_processing_thread(&dns, &conn_record),
                    Err(e) => eprintln!("DNS channel error: {}", e),
                }
            }
        }
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

fn tls_processing_thread(tls: &TlsHandshake, conn_record: &ConnRecord) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
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

fn dns_processing_thread(dns: &DnsTransaction, conn_record: &ConnRecord) {
    println!("DNS query domain: {}, conn. metrics: {:?}", dns.query_domain(), conn_record);
}

#[retina_main(2)]
fn main() {
    let processing_cores = vec![1, 2, 3];
    let rx_cores = vec![0];
    let channel_size = 100000;
    
    init_processing_threads(processing_cores, rx_cores, channel_size);
    
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
