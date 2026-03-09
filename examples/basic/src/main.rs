use array_init::array_init;
use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::{ConnRecord, connection::N_PACKETS};
use retina_filtergen::{filter, retina_main};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

const NUM_CORES: usize = 16;
const ARR_LEN: usize = NUM_CORES + 1;
const OUTFILE_PREFIX: &str = "flow_features_";
const OUTFILE: &str = "flow_features.csv";

const OUTFILE_PREFIX_TLS: &str = "flow_features_tls_";
const OUTFILE_TLS: &str = "flow_features_tls.csv";

const CSV_HEADER: &str =
    "src_ip_subn,dst_ip_subn,src_port,dst_port,protocol,\
     total_pkts,total_pkt_bytes,total_payload_bytes,\
     orig_pkts,orig_pkt_bytes,orig_payload_bytes,orig_content_gaps,orig_missed_bytes,\
     resp_pkts,resp_pkt_bytes,resp_payload_bytes,resp_content_gaps,resp_missed_bytes,\
     duration_ms,max_inactivity_ms,time_to_second_pkt_ms,\
     final_total_payload_bytes,final_duration_ms\n";

pub struct FlowFeatures {
    pub src_ip_subn:             u128,
    pub dst_ip_subn:             u128,
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
    pub final_duration_ms:         u128,
}

fn ip_to_prefix(ip: &std::net::IpAddr) -> u128 {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // /24
            let prefix = u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
            prefix as u128
        }
        std::net::IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            // /48
            let mut prefix_bytes = [0u8; 16];
            prefix_bytes[..6].copy_from_slice(&octets[..6]);
            u128::from_be_bytes(prefix_bytes)
        }
    }
}

fn extract_features(conn: &ConnRecord) -> Option<FlowFeatures> {
    if (conn.total_pkts() as usize) < N_PACKETS {
        return None;
    }
    let prefix_orig = conn.prefix_orig.as_ref()?;
    let prefix_resp = conn.prefix_resp.as_ref()?;

    Some(FlowFeatures {
        src_ip_subn:               ip_to_prefix(&conn.five_tuple.orig.ip()),
        dst_ip_subn:               ip_to_prefix(&conn.five_tuple.resp.ip()),
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
        final_duration_ms:         conn.duration().as_millis(),
    })
}

fn serialize_csv_row(f: &FlowFeatures) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        f.src_ip_subn,
        f.dst_ip_subn,
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
        f.final_duration_ms,
    )
}

static RESULTS: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();
static RESULTS_TLS: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();

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

fn results_tls() -> &'static [AtomicPtr<BufWriter<File>>; ARR_LEN] {
    RESULTS_TLS.get_or_init(|| {
        let mut ptrs = vec![];
        for core_id in 0..ARR_LEN {
            let path = format!("{}{}.csv", OUTFILE_PREFIX_TLS, core_id);
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

fn write_row_tls(row: &str, core_id: &CoreId) {
    let ptr = results_tls()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    wtr.write_all(row.as_bytes()).unwrap();
}

fn combine_results() {
    println!("Combining results from {} cores...", ARR_LEN);
    let mut output = Vec::new();
    let mut output_tls = Vec::new();

    output.extend_from_slice(CSV_HEADER.as_bytes());
    output_tls.extend_from_slice(CSV_HEADER.as_bytes());

    for core_id in 0..ARR_LEN {
        let ptr = results()[core_id].load(Ordering::Relaxed);
        let wtr = unsafe { &mut *ptr };
        wtr.flush().unwrap();

        let path = format!("{}{}.csv", OUTFILE_PREFIX, core_id);
        let content = std::fs::read(&path).unwrap();
        output.extend_from_slice(&content);
        std::fs::remove_file(&path).unwrap();

        let ptr = results_tls()[core_id].load(Ordering::Relaxed);
        let wtr = unsafe { &mut *ptr };
        wtr.flush().unwrap();
        let path = format!("{}{}.csv", OUTFILE_PREFIX_TLS, core_id);
        let content = std::fs::read(&path).unwrap();
        output_tls.extend_from_slice(&content);
        std::fs::remove_file(&path).unwrap();
    }

    std::fs::write(OUTFILE, &output).unwrap();
    std::fs::write(OUTFILE_TLS, &output_tls).unwrap();
    println!("Written to {}; {}", OUTFILE, OUTFILE_TLS);
}

#[filter("tcp or udp")]
fn flow_cb(conn: &ConnRecord, core_id: &CoreId) {
    if let Some(features) = extract_features(conn) {
        write_row(&serialize_csv_row(&features), core_id);
    }
}

#[filter("tls or quic")]
fn flow_cb_tls_quic(conn: &ConnRecord, core_id: &CoreId) {
    if let Some(features) = extract_features(conn) {
        write_row_tls(&serialize_csv_row(&features), core_id);
    }
}

#[retina_main(2)]
fn main() {
    let _ = results();

    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    combine_results();
}
