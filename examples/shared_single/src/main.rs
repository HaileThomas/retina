use retina_core::{config::default_config, Runtime}; 
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};

use std::thread;
use crossbeam::channel::{bounded, select, Sender, Receiver}; 
use once_cell::sync::OnceCell;  
use nix::sched::{sched_setaffinity, CpuSet}; 
use nix::unistd::Pid; 
 
static TLS_SENDER: OnceCell<Sender<(TlsHandshake, ConnRecord)>> = OnceCell::new(); 
static DNS_SENDER: OnceCell<Sender<(DnsTransaction, ConnRecord)>> = OnceCell::new(); 

// spawns threads pinned to specified cores
fn init_processing_threads(cores: Vec<usize>, channel_size: usize){
    let (tls_sender, tls_receiver) = bounded::<(TlsHandshake, ConnRecord)>(channel_size);
    let (dns_sender, dns_receiver) = bounded::<(DnsTransaction, ConnRecord)>(channel_size); 

    TLS_SENDER.set(tls_sender).expect("TLS Sender already initialized.");
    DNS_SENDER.set(dns_sender).expect("DNS Sender already initialized."); 

    for core in cores {
        let tls_receiver_clone = tls_receiver.clone(); 
        let dns_receiver_clone = dns_receiver.clone(); 

        thread::spawn(move || {
            let mut cpu_set = CpuSet::new();
            
            if cpu_set.set(core).is_ok() {
                if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpu_set) {
                    eprintln!("Failed to set CPU affinity: {}", e); 
                } else {
                    println!("Thread pinned to core {}.", core);
                }
            }

            process_subscriptions(tls_receiver_clone, dns_receiver_clone); 
        });
    }

}

fn process_subscriptions(
    tls_receiver: Receiver<(TlsHandshake, ConnRecord)>,
    dns_receiver: Receiver<(DnsTransaction, ConnRecord)>
) {
    loop {
        select! {
            recv(tls_receiver) -> msg => {
                match msg {
                    Ok((tls, conn_record)) => tls_processing_thread(&tls, &conn_record),
                    Err(e) => eprintln!("TLS channel error: {}", e),
                }
            }

            recv(dns_receiver) -> msg => {
                match msg {
                    Ok((dns, conn_record)) => dns_processing_thread(&dns, &conn_record), 
                    Err(e) => eprintln!("DNS channel error: {}", e), 
                }
            }
        }
    }
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    if let Some(sender) = TLS_SENDER.get() {         
        if let Err(e) = sender.send((tls.clone(), conn_record.clone())) {
            eprintln!("Failed to send TLS data through channel: {}", e); 
        }
    } else {
        eprintln!("TLS sender not initialized"); 
    }
}

// Process TLS data in a dedicated thread. 
fn tls_processing_thread(tls: &TlsHandshake, conn_record: &ConnRecord) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}


#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
    if let Some(sender) = DNS_SENDER.get() {
        if let Err(e) = sender.send((dns.clone(), conn_record.clone())) {
            eprintln!("Failed to send DNS data through chhanel: {}", e); 
        }
    } else {
        eprintln!("DNS sender not initialized."); 
    }
}


// Process DNS data in a dedicated thread. 
fn dns_processing_thread(dns: &DnsTransaction, conn_record: &ConnRecord) {
    println!("DNS query domain: {}, conn. metrics: {:?}", dns.query_domain(), conn_record);
}

#[retina_main(2)]
fn main() {
    // user-provided through macro attribute per callback     
    let processing_cores = vec![1, 2, 3]; 
    let channel_size = 100000; 

    // check whether processing cores and rx cores disjoint (required) 
    init_processing_threads(processing_cores, channel_size);  

    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}


