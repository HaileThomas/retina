use array_init::array_init;
use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main, streaming};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

const NUM_CORES: usize = 16;
const ARR_LEN: usize = NUM_CORES + 1;
const N_PACKETS: usize = 10;
const OUTFILE_PREFIX: &str = "flow_features_";
const OUTFILE: &str = "flow_features.csv";
const CSV_HEADER: &str =
    "src_ip,dst_ip,src_port,dst_port,protocol,\
     total_pkts,total_pkt_bytes,total_payload_bytes,\
     orig_pkts,orig_pkt_bytes,orig_payload_bytes,orig_content_gaps,orig_missed_bytes,\
     resp_pkts,resp_pkt_bytes,resp_payload_bytes,resp_content_gaps,resp_missed_bytes,\
     duration_ms,max_inactivity_ms,time_to_second_pkt_ms\n";

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
}

fn extract_features(conn: &ConnRecord, n_packets: usize) -> Option<FlowFeatures> {
    if conn.total_pkts() < n_packets as u64 {
        return None;
    }

    Some(FlowFeatures {
        src_ip:                conn.five_tuple.orig.ip(),
        dst_ip:                conn.five_tuple.resp.ip(),
        src_port:              conn.five_tuple.orig.port(),
        dst_port:              conn.five_tuple.resp.port(),
        protocol:              conn.five_tuple.proto,
        total_pkts:            conn.total_pkts(),
        total_pkt_bytes:       conn.total_pkt_bytes(),
        total_payload_bytes:   conn.total_payload_bytes(),
        orig_pkts:             conn.orig.nb_pkts,
        orig_pkt_bytes:        conn.orig.nb_pkt_bytes,
        orig_payload_bytes:    conn.orig.nb_payload_bytes,
        orig_content_gaps:     conn.orig.content_gaps(),
        orig_missed_bytes:     conn.orig.missed_bytes(),
        resp_pkts:             conn.resp.nb_pkts,
        resp_pkt_bytes:        conn.resp.nb_pkt_bytes,
        resp_payload_bytes:    conn.resp.nb_payload_bytes,
        resp_content_gaps:     conn.resp.content_gaps(),
        resp_missed_bytes:     conn.resp.missed_bytes(),
        duration_ms:           conn.duration().as_millis(),
        max_inactivity_ms:     conn.max_inactivity.as_millis(),
        time_to_second_pkt_ms: conn.time_to_second_packet().as_millis(),
    })
}

fn serialize_csv_row(f: &FlowFeatures) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
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

#[filter("tcp")]
#[streaming("packets=1")]
fn flow_cb(conn: &ConnRecord, core_id: &CoreId) -> bool {
    if let Some(features) = extract_features(conn, N_PACKETS) {
        write_row(&serialize_csv_row(&features), core_id);
        return false;
    }
    true
}

#[retina_main(1)]
fn main() {
    let _ = results();
    
    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    combine_results();
}
