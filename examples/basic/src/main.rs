use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::ConnRecord;
use retina_filtergen::{filter, retina_main};

mod flow_features;
mod csv_output;

use flow_features::FlowFeatures;

#[filter("tcp or udp")]
fn flow_cb(conn: &ConnRecord, core_id: &CoreId) {
    if let Some(features) = FlowFeatures::from_conn(conn) {
        csv_output::write(&features, core_id);
    }
}

#[filter("tls or quic")]
fn flow_cb_tls_quic(conn: &ConnRecord, core_id: &CoreId) {
    if let Some(features) = FlowFeatures::from_conn(conn) {
        csv_output::write_tls(&features, core_id);
    }
}

#[retina_main(2)]
fn main() {
    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    csv_output::combine();
}
