use array_init::array_init;
use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

const NUM_CORES: usize = 16;
const ARR_LEN: usize = NUM_CORES + 1;
const OUTFILE_PREFIX: &str = "flow_features_";
const OUTFILE: &str = "flow_features.csv";
const CSV_HEADER: &str =
    "src_ip,dst_ip,src_port,dst_port,protocol,\
     total_pkts,total_pkt_bytes,total_payload_bytes,\
     orig_pkts,orig_pkt_bytes,orig_payload_bytes,orig_content_gaps,orig_missed_bytes,\
     resp_pkts,resp_pkt_bytes,resp_payload_bytes,resp_content_gaps,resp_missed_bytes,\
     duration_ms,max_inactivity_ms,time_to_second_pkt_ms,\
     final_total_payload_bytes\n";

pub struct FlowFeatures {
    pub src_ip:                  std::net::IpAddr,
    pub dst_ip:                  std::net::IpAddr,
    pub src_port:                u16,
    pub dst_port:                u16,
    pub protocol:                usize,
    pub total_pkts:              u64,
    pub total_pkt_bytes:         u64,
    pub total_payload_bytes:     u64,
    pub orig_pkts:               u64,
    pub orig_pkt_bytes:          u64,
    pub orig_payload_bytes:      u64,
    pub orig_content_gaps:       u64,
    pub orig_missed_bytes:       u64,
    pub resp_pkts:               u64,
    pub resp_pkt_bytes:          u64,
    pub resp_payload_bytes:      u64,
    pub resp_content_gaps:       u64,
    pub resp_missed_bytes:       u64,
    pub duration_ms:             u128,
    pub max_inactivity_ms:       u128,
    pub time_to_second_pkt_ms:   u128,
    pub final_total_payload_bytes: u64,
}

fn extract_features(conn: &ConnRecord) -> Option<FlowFeatures> {
    let prefix_orig = conn.prefix_orig.as_ref()?;
    let prefix_resp = conn.prefix_resp.as_ref()?;

    Some(FlowFeatures {
        src_ip:                    conn.five_tuple.orig.ip(),
        dst_ip:                    conn.five_tuple.resp.ip(),
        src_port:                  conn.five_tuple.orig.port(),
        dst_port:                  conn.five_tuple.resp.port(),
        protocol:                  conn.five_tuple.proto,
        total_pkts:                prefix_orig.nb_pkts + prefix_resp.nb_pkts,
        total_pkt_bytes:           prefix_orig.nb_pkt_bytes + prefix_resp.nb_pkt_bytes,
        total_payload_bytes:       prefix_orig.nb_payload_bytes + prefix_resp.nb_payload_bytes,
        orig_pkts:                 prefix_orig.nb_pkts,
        orig_pkt_bytes:            prefix_orig.nb_pkt_bytes,
        orig_payload_bytes:        prefix_orig.nb_payload_bytes,
        orig_content_gaps:         prefix_orig.content_gaps(),
        orig_missed_bytes:         prefix_orig.missed_bytes(),
        resp_pkts:                 prefix_resp.nb_pkts,
        resp_pkt_bytes:            prefix_resp.nb_pkt_bytes,
        resp_payload_bytes:        prefix_resp.nb_payload_bytes,
        resp_content_gaps:         prefix_resp.content_gaps(),
        resp_missed_bytes:         prefix_resp.missed_bytes(),
        duration_ms:               conn.prefix_duration.unwrap().as_millis(),
        max_inactivity_ms:         conn.prefix_max_inactivity.unwrap().as_millis(),
        time_to_second_pkt_ms:     conn.prefix_time_to_second_pkt.unwrap().as_millis(),
        final_total_payload_bytes: conn.orig.nb_payload_bytes + conn.resp.nb_payload_bytes,
    })
}

fn serialize_csv_row(f: &FlowFeatures) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        f.src_ip,
        f.dst_ip,
        f.src_port,
        f.dst_port,
        f.protocol,
        f.total_pkts,
        f.total_pkt_bytes,
        f.total_payload_bytes,
        f.orig_pkts,
        f.orig_pkt_bytes,
        f.orig_payload_bytes,
        f.orig_content_gaps,
        f.orig_missed_bytes,
        f.resp_pkts,
        f.resp_pkt_bytes,
        f.resp_payload_bytes,
        f.resp_content_gaps,
        f.resp_missed_bytes,
        f.duration_ms,
        f.max_inactivity_ms,
        f.time_to_second_pkt_ms,
        f.final_total_payload_bytes,
    )
}

static RESULTS: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();

fn results() -> &'static [AtomicPtr<BufWriter<File>>; ARR_LEN] {
    RESULTS.get_or_init(|| {
        let mut ptrs = vec![];
        for core_id in 0..ARR_LEN {
            let path = format!("{}{}.csv", OUTFILE_PREFIX, core_id);
            let wtr = BufWriter::new(File::create(&path).unwrap());
            ptrs.push(Box::into_raw(Box::new(wtr)));
        }
        array_init(|i| AtomicPtr::new(ptrs[i]))
    })
}

fn write_row(row: &str, core_id: &CoreId) {
    let ptr = results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    wtr.write_all(row.as_bytes()).unwrap();
}

fn combine_results() {
    println!("Combining results from {} cores...", ARR_LEN);
    let mut output = Vec::new();

    output.extend_from_slice(CSV_HEADER.as_bytes());

    for core_id in 0..ARR_LEN {
        let ptr = results()[core_id].load(Ordering::Relaxed);
        let wtr = unsafe { &mut *ptr };
        wtr.flush().unwrap();

        let path = format!("{}{}.csv", OUTFILE_PREFIX, core_id);
        let content = std::fs::read(&path).unwrap();
        output.extend_from_slice(&content);
        std::fs::remove_file(&path).unwrap();
    }

    std::fs::write(OUTFILE, &output).unwrap();
    println!("Written to {}", OUTFILE);
}

#[filter("tcp or udp")]
fn flow_cb(conn: &ConnRecord, core_id: &CoreId) {
    if let Some(features) = extract_features(conn) {
        write_row(&serialize_csv_row(&features), core_id);
    }
}

#[retina_main(1)]
fn main() {
    let _ = results();

    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    combine_results();
}
