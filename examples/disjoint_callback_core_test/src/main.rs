use retina_core::{config::default_config, Runtime}; 
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};

use std::thread;
use crossbeam::channel::{bounded, Sender, Receiver}; 
use once_cell::sync::OnceCell;  
use nix::sched::{sched_setaffinity, CpuSet}; 
use nix::unistd::Pid; 
 
static TLS_SENDER: OnceCell<Sender<(TlsHandshake, ConnRecord)>> = OnceCell::new(); 
static DNS_SENDER: OnceCell<Sender<(DnsTransaction, ConnRecord)>> = OnceCell::new(); 

// spawns threads (dedicated to handling particular callback) pinned to specific cores
fn init_processing_threads<T: std::marker::Send + 'static>(
    sender_cell: &OnceCell<Sender<T>>, 
    cores: Vec<usize>, 
    thread_fn: fn(Receiver<T>),
    channel_size: usize
){
    let (sender, receiver) = bounded::<T>(channel_size); 
    sender_cell.set(sender).expect("Senders already initialized.");
 
    for core in cores {
        let receiver_clone = receiver.clone();

        thread::spawn(move || {
            let mut cpu_set = CpuSet::new();
            
            if cpu_set.set(core).is_ok() {
                if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpu_set) {
                    eprintln!("Failed to set CPU affinity: {}", e); 
                } else {
                    println!("Thread pinned to core {}.", core);
                }

                thread_fn(receiver_clone);
            }
        });
    }

}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    if let Some(sender) = TLS_SENDER.get() {         
        if let Err(e) = sender.try_send((tls.clone(), conn_record.clone())) {
            eprintln!("Failed to send TLS data through channel: {}", e); 
        }
    } else {
        eprintln!("TLS sender not initialized"); 
    }
}

// Process TLS data in a dedicated thread. 
fn tls_processing_thread(receiver: Receiver<(TlsHandshake, ConnRecord)>) {
    println!("TLS processing thread started!");

    for (tls, conn_record) in receiver {
        println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
    }
}


#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
    if let Some(sender) = DNS_SENDER.get() {
        if let Err(e) = sender.try_send((dns.clone(), conn_record.clone())) {
            eprintln!("Failed to send DNS data through chhanel: {}", e); 
        }
    } else {
        eprintln!("DNS sender not initialized."); 
    }
}


// Process DNS data in a dedicated thread. 
fn dns_processing_thread(receiver: Receiver<(DnsTransaction, ConnRecord)>) {
    println!("DNS processing thread started!");

    for (dns, conn_record) in receiver {
        println!("DNS query domain: {}, conn. metrics: {:?}", 
            dns.query_domain(), 
            conn_record);
    }
}

#[retina_main(2)]
fn main() {
    // user-provided through macro attribute per callback     
    let tls_processing_cores = vec![1, 2]; 
    let dns_processing_cores = vec![3];

    // setting size on a per-channel basis gives the user more flexibility, 
    // if they know relative percentages for incoming traffic 
    let tls_channel_size = 100000; 
    let dns_channel_size = 100000; 

    // 1. check whether processing cores are disjoint (optional) 
    // 2. check whether processing cores and rx cores disjoint (required) 
    
    // launch threads for each callback
    init_processing_threads::<(TlsHandshake, ConnRecord)>(
        &TLS_SENDER, 
        tls_processing_cores, 
        tls_processing_thread,
        tls_channel_size 
    );
    init_processing_threads::<(DnsTransaction, ConnRecord)>(
        &DNS_SENDER, 
        dns_processing_cores, 
        dns_processing_thread,
        dns_channel_size
    ); 

    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
