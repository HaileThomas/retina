use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, TlsHandshake};
use retina_filtergen::{subscription};
use serde_json::{json, Value};
use std::sync::Mutex; 

lazy_static::lazy_static! {
    static ref output_array: Mutex<Vec<Value>> = Mutex::new(Vec::new()); 
}

fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    let output = json!({
        "Tls SNI": tls.sni(),
        "conn. metrics": conn_record
    }); 

    let mut oa = output_array.lock().unwrap(); 
    oa.push(output);
}

#[subscription("./examples/my_simple/spec.toml")]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    let oa = output_array.lock().unwrap(); 
    println!("{}", serde_json::to_string_pretty(&*oa).unwrap());
}
