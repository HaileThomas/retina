use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_datatypes::conn_fts::InterArrivals;
use retina_filtergen::{filter, retina_main};

mod conn_features;
mod dns_features;
mod tls_features;
mod headers;
mod csv_output;
mod hash_utils;

use conn_features::ConnFeatures;
use dns_features::DnsFeatures;
use tls_features::TlsFeatures;

#[filter("tcp or udp")]
fn flow_cb(conn: &ConnRecord, iat: &InterArrivals, core_id: &CoreId) {
    if let Some(features) = ConnFeatures::from_conn(conn, iat) {
        csv_output::write(&features, core_id);
    }
}

#[filter("tls or quic")]
fn flow_cb_tls(conn: &ConnRecord, iat: &InterArrivals, proto: &TlsHandshake, core_id: &CoreId) {
    if let (Some(conn_features), Some(tls_features)) = (
        ConnFeatures::from_conn(conn, iat),
        TlsFeatures::from_tls(proto),
    ) {
        csv_output::write_tls(&conn_features, &tls_features, core_id);
    }
}

#[filter("dns")]
fn flow_cb_dns(conn: &ConnRecord, iat: &InterArrivals, proto: &DnsTransaction, core_id: &CoreId) {
    if let (Some(conn_features), Some(dns_features)) = (
        ConnFeatures::from_conn(conn, iat),
        DnsFeatures::from_dns(proto, conn.client().ip()),
    ) {
        csv_output::write_dns(&conn_features, &dns_features, core_id);
    }
}

#[retina_main(3)]
fn main() {
    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    csv_output::combine();
}
