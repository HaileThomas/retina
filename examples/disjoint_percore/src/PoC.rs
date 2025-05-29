use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};

#[filter("tls")]
#[pin_callbacks([1, 2, 4]) 
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}

#[filter("dns")]
#[pin_callbacks([3, 5]) 
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
    println!(
        "DNS query domain: {}, conn. metrics: {:?}",
        dns.query_domain(),
        conn_record
    );
}

#[retina_main(2)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
