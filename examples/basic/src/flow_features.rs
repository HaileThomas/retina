use retina_datatypes::{ConnRecord, connection::N_PACKETS};
use serde::Serialize;

#[derive(Serialize)]
pub struct FlowFeatures {
    pub src_ip_subn: u128,
    pub dst_ip_subn: u128,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: usize,
    pub total_pkts: u64,
    pub total_pkt_bytes: u64,
    pub total_payload_bytes: u64,
    pub orig_pkts: u64,
    pub orig_pkt_bytes: u64,
    pub orig_payload_bytes: u64,
    pub orig_content_gaps: u64,
    pub orig_missed_bytes: u64,
    pub resp_pkts: u64,
    pub resp_pkt_bytes: u64,
    pub resp_payload_bytes: u64,
    pub resp_content_gaps: u64,
    pub resp_missed_bytes: u64,
    pub duration_ms: u128,
    pub max_inactivity_ms: u128,
    pub time_to_second_pkt_ms: u128,
    pub final_total_payload_bytes: u64,
    pub final_duration_ms: u128,
}

fn ip_to_prefix(ip: &std::net::IpAddr) -> u128 {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let prefix = u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
            prefix as u128
        }
        std::net::IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            let mut prefix_bytes = [0u8; 16];
            prefix_bytes[..6].copy_from_slice(&octets[..6]);
            u128::from_be_bytes(prefix_bytes)
        }
    }
}

impl FlowFeatures {
    pub const HEADER: &'static str =
        "src_ip_subn,dst_ip_subn,src_port,dst_port,protocol,\
         total_pkts,total_pkt_bytes,total_payload_bytes,\
         orig_pkts,orig_pkt_bytes,orig_payload_bytes,orig_content_gaps,orig_missed_bytes,\
         resp_pkts,resp_pkt_bytes,resp_payload_bytes,resp_content_gaps,resp_missed_bytes,\
         duration_ms,max_inactivity_ms,time_to_second_pkt_ms,\
         final_total_payload_bytes,final_duration_ms\n";
    
    pub fn from_conn(conn: &ConnRecord) -> Option<Self> {
        if (conn.total_pkts() as usize) < N_PACKETS {
            return None;
        }

        let prefix_orig = conn.prefix_orig.as_ref()?;
        let prefix_resp = conn.prefix_resp.as_ref()?;

        Some(Self {
            src_ip_subn: ip_to_prefix(&conn.five_tuple.orig.ip()),
            dst_ip_subn: ip_to_prefix(&conn.five_tuple.resp.ip()),
            src_port: conn.five_tuple.orig.port(),
            dst_port: conn.five_tuple.resp.port(),
            protocol: conn.five_tuple.proto,

            total_pkts: prefix_orig.nb_pkts + prefix_resp.nb_pkts,
            total_pkt_bytes: prefix_orig.nb_pkt_bytes + prefix_resp.nb_pkt_bytes,
            total_payload_bytes: prefix_orig.nb_payload_bytes + prefix_resp.nb_payload_bytes,

            orig_pkts: prefix_orig.nb_pkts,
            orig_pkt_bytes: prefix_orig.nb_pkt_bytes,
            orig_payload_bytes: prefix_orig.nb_payload_bytes,
            orig_content_gaps: prefix_orig.content_gaps(),
            orig_missed_bytes: prefix_orig.missed_bytes(),

            resp_pkts: prefix_resp.nb_pkts,
            resp_pkt_bytes: prefix_resp.nb_pkt_bytes,
            resp_payload_bytes: prefix_resp.nb_payload_bytes,
            resp_content_gaps: prefix_resp.content_gaps(),
            resp_missed_bytes: prefix_resp.missed_bytes(),

            duration_ms: conn.prefix_duration.unwrap().as_millis(),
            max_inactivity_ms: conn.prefix_max_inactivity.unwrap().as_millis(),
            time_to_second_pkt_ms: conn.prefix_time_to_second_pkt.unwrap().as_millis(),

            final_total_payload_bytes: conn.orig.nb_payload_bytes + conn.resp.nb_payload_bytes,
            final_duration_ms: conn.duration().as_millis(),
        })
    }
}