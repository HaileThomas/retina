use retina_datatypes::DnsTransaction;
use retina_core::protocols::stream::dns::Data;
use serde::Serialize;
use std::net::IpAddr;
use crate::hash_utils::hash_ip;

#[derive(Clone, Debug, Serialize)]
pub struct DnsFeatures {
    pub client_ip_hash:               u64,  // hash of querying client IP
    pub resolved_ip_hash_a:           u64,  // hash of first A record answer IP, 0 if none
    pub resolved_ip_hash_aaaa:        u64,  // hash of first AAAA record answer IP, 0 if none
    
    pub query_num_questions:          u16,  // number of questions in query section (typically 1)
    pub query_recursion_desired:      u8,   // RD bit set in query (0/1)
    pub has_query:                    u8,   // 1 if a query was observed, 0 if response-only

    pub has_response:                 u8,   // 1 if a response was observed, 0 if query-only
    pub response_code:                u8,   // RCODE: 0=NoError 1=FormErr 2=ServFail 3=NXDomain 4=NotImp 5=Refused
    pub response_authoritative:       u8,   // AA bit set in response (0/1)
    pub response_recursion_available: u8,   // RA bit set in response (0/1)
    pub response_num_answers:         u16,  // record count in Answer section
    pub response_num_nameservers:     u16,  // record count in Authority section
    pub response_num_additional:      u16,  // record count in Additional section

    pub answer_num_a:                 u16,  // A (IPv4) records in Answer
    pub answer_num_aaaa:              u16,  // AAAA (IPv6) records in Answer
    pub answer_num_cname:             u16,  // CNAME records in Answer
    pub answer_num_mx:                u16,  // MX records in Answer
    pub answer_num_ns:                u16,  // NS records in Answer
    pub answer_num_ptr:               u16,  // PTR records in Answer
    pub answer_num_soa:               u16,  // SOA records in Answer
    pub answer_num_srv:               u16,  // SRV records in Answer
    pub answer_num_txt:               u16,  // TXT records in Answer
    pub answer_num_unknown:           u16,  // Unknown-type records in Answer

    pub ns_num_ns:                    u16,  // NS records in Authority section
    pub ns_num_soa:                   u16,  // SOA records in Authority section (present on NXDOMAIN)
    pub ns_num_other:                 u16,  // other record types in Authority section

    pub additional_num_a:             u16,  // A records in Additional section
    pub additional_num_aaaa:          u16,  // AAAA records in Additional section
    pub additional_num_other:         u16,  // other record types in Additional section
}


impl DnsFeatures {
    pub fn from_dns(dns: &DnsTransaction, client_ip: IpAddr) -> Option<Self> {
        if dns.query.is_none() && dns.response.is_none() {
            return None;
        }

        let client_ip_hash = hash_ip(client_ip);

        // Extract first A and AAAA answer for join key
        let mut resolved_ip_hash_a    = 0u64;
        let mut resolved_ip_hash_aaaa = 0u64;
        if let Some(resp) = &dns.response {
            for rec in &resp.answers {
                match &rec.data {
                    Data::A(a) if resolved_ip_hash_a == 0 => {
                        resolved_ip_hash_a = hash_ip(IpAddr::V4(a.0));
                    }
                    Data::Aaaa(a) if resolved_ip_hash_aaaa == 0 => {
                        resolved_ip_hash_aaaa = hash_ip(IpAddr::V6(a.0));
                    }
                    _ => {}
                }
            }
        }

        let (query_num_questions, query_recursion_desired, has_query) =
            if let Some(q) = &dns.query {
                (q.num_questions, q.recursion_desired as u8, 1u8)
            } else {
                (0, 0, 0u8)
            };

        let (has_response, response_code, response_authoritative,
             response_recursion_available, response_num_answers,
             response_num_nameservers, response_num_additional) =
            if let Some(r) = &dns.response {
                (1u8,
                 match format!("{:?}", r.response_code).as_str() {
                     "NoError"        => 0u8,
                     "FormatError"    => 1,
                     "ServerFailure"  => 2,
                     "NameError"      => 3,
                     "NotImplemented" => 4,
                     "Refused"        => 5,
                     _                => 255,
                 },
                 r.authoritative as u8,
                 r.recursion_available as u8,
                 r.num_answers,
                 r.num_nameservers,
                 r.num_additional)
            } else {
                (0u8, 0, 0, 0, 0, 0, 0)
            };

        let mut answer_num_a       = 0u16;
        let mut answer_num_aaaa    = 0u16;
        let mut answer_num_cname   = 0u16;
        let mut answer_num_mx      = 0u16;
        let mut answer_num_ns      = 0u16;
        let mut answer_num_ptr     = 0u16;
        let mut answer_num_soa     = 0u16;
        let mut answer_num_srv     = 0u16;
        let mut answer_num_txt     = 0u16;
        let mut answer_num_unknown = 0u16;

        if let Some(resp) = &dns.response {
            for rec in &resp.answers {
                match &rec.data {
                    Data::A(_)     => answer_num_a       += 1,
                    Data::Aaaa(_)  => answer_num_aaaa    += 1,
                    Data::Cname(_) => answer_num_cname   += 1,
                    Data::Mx(_)    => answer_num_mx      += 1,
                    Data::Ns(_)    => answer_num_ns      += 1,
                    Data::Ptr(_)   => answer_num_ptr     += 1,
                    Data::Soa(_)   => answer_num_soa     += 1,
                    Data::Srv(_)   => answer_num_srv     += 1,
                    Data::Txt(_)   => answer_num_txt     += 1,
                    Data::Unknown  => answer_num_unknown += 1,
                }
            }
        }

        let mut ns_num_ns    = 0u16;
        let mut ns_num_soa   = 0u16;
        let mut ns_num_other = 0u16;

        if let Some(resp) = &dns.response {
            for rec in &resp.nameservers {
                match &rec.data {
                    Data::Ns(_)  => ns_num_ns  += 1,
                    Data::Soa(_) => ns_num_soa += 1,
                    _            => ns_num_other += 1,
                }
            }
        }

        let mut additional_num_a     = 0u16;
        let mut additional_num_aaaa  = 0u16;
        let mut additional_num_other = 0u16;

        if let Some(resp) = &dns.response {
            for rec in &resp.additionals {
                match &rec.data {
                    Data::A(_)    => additional_num_a    += 1,
                    Data::Aaaa(_) => additional_num_aaaa += 1,
                    _             => additional_num_other += 1,
                }
            }
        }

        Some(Self {
            client_ip_hash,
            resolved_ip_hash_a,
            resolved_ip_hash_aaaa,
            query_num_questions,
            query_recursion_desired,
            has_query,
            has_response,
            response_code,
            response_authoritative,
            response_recursion_available,
            response_num_answers,
            response_num_nameservers,
            response_num_additional,
            answer_num_a,
            answer_num_aaaa,
            answer_num_cname,
            answer_num_mx,
            answer_num_ns,
            answer_num_ptr,
            answer_num_soa,
            answer_num_srv,
            answer_num_txt,
            answer_num_unknown,
            ns_num_ns,
            ns_num_soa,
            ns_num_other,
            additional_num_a,
            additional_num_aaaa,
            additional_num_other,
        })
    }
}

// #[derive(Serialize)]
// pub struct DnsConnFeatures {
//     // ConnFeatures fields
//     pub src_ip_subn: u128,
//     pub dst_ip_subn: u128,
//     pub src_port: u16,
//     pub dst_port: u16,
//     pub protocol: usize,
//     pub duration_ms: u128,
//     pub max_inactivity_ms: u128,
//     pub time_to_second_pkt_ms: u128,
//     pub hist_syn: u8,
//     pub hist_synack: u8,
//     pub hist_ack: u8,
//     pub hist_data: u8,
//     pub hist_fin: u8,
//     pub hist_rst: u8,
//     pub hist_syn_r: u8,
//     pub hist_synack_r: u8,
//     pub hist_ack_r: u8,
//     pub hist_data_r: u8,
//     pub hist_fin_r: u8,
//     pub hist_rst_r: u8,
//     pub orig_nb_pkts: u64,
//     pub orig_nb_malformed_pkts: u64,
//     pub orig_nb_late_start_pkts: u64,
//     pub orig_nb_pkt_bytes: u64,
//     pub orig_nb_payload_bytes: u64,
//     pub orig_max_simult_gaps: u64,
//     pub orig_content_gaps: u64,
//     pub orig_missed_bytes: u64,
//     pub orig_mean_pkts_to_fill: f64,
//     pub orig_median_pkts_to_fill: u64,
//     pub resp_nb_pkts: u64,
//     pub resp_nb_malformed_pkts: u64,
//     pub resp_nb_late_start_pkts: u64,
//     pub resp_nb_pkt_bytes: u64,
//     pub resp_nb_payload_bytes: u64,
//     pub resp_max_simult_gaps: u64,
//     pub resp_content_gaps: u64,
//     pub resp_missed_bytes: u64,
//     pub resp_mean_pkts_to_fill: f64,
//     pub resp_median_pkts_to_fill: u64,
//     pub orig_iat_mean: f64,
//     pub orig_iat_median: f64,
//     pub orig_iat_min: u128,
//     pub orig_iat_max: u128,
//     pub orig_iat_std: f64,
//     pub resp_iat_mean: f64,
//     pub resp_iat_median: f64,
//     pub resp_iat_min: u128,
//     pub resp_iat_max: u128,
//     pub resp_iat_std: f64,
//     pub final_total_payload_bytes: u64,
//     pub final_duration_ms: u128,
//     // DnsFeatures fields
//     pub query_num_questions: u16,
//     pub query_recursion_desired: u8,
//     pub has_query: u8,
//     pub has_response: u8,
//     pub response_code: u8,
//     pub response_authoritative: u8,
//     pub response_recursion_available: u8,
//     pub response_num_answers: u16,
//     pub response_num_nameservers: u16,
//     pub response_num_additional: u16,
//     pub answer_num_a: u16,
//     pub answer_num_aaaa: u16,
//     pub answer_num_cname: u16,
//     pub answer_num_mx: u16,
//     pub answer_num_ns: u16,
//     pub answer_num_ptr: u16,
//     pub answer_num_soa: u16,
//     pub answer_num_srv: u16,
//     pub answer_num_txt: u16,
//     pub answer_num_unknown: u16,
//     pub ns_num_ns: u16,
//     pub ns_num_soa: u16,
//     pub ns_num_other: u16,
//     pub additional_num_a: u16,
//     pub additional_num_aaaa: u16,
//     pub additional_num_other: u16,
// }

// impl DnsConnFeatures {
//     pub fn new(conn: ConnFeatures, dns: DnsFeatures) -> Self {
//         Self {
//             src_ip_subn: conn.src_ip_subn,
//             dst_ip_subn: conn.dst_ip_subn,
//             src_port: conn.src_port,
//             dst_port: conn.dst_port,
//             protocol: conn.protocol,
//             duration_ms: conn.duration_ms,
//             max_inactivity_ms: conn.max_inactivity_ms,
//             time_to_second_pkt_ms: conn.time_to_second_pkt_ms,
//             hist_syn: conn.hist_syn,
//             hist_synack: conn.hist_synack,
//             hist_ack: conn.hist_ack,
//             hist_data: conn.hist_data,
//             hist_fin: conn.hist_fin,
//             hist_rst: conn.hist_rst,
//             hist_syn_r: conn.hist_syn_r,
//             hist_synack_r: conn.hist_synack_r,
//             hist_ack_r: conn.hist_ack_r,
//             hist_data_r: conn.hist_data_r,
//             hist_fin_r: conn.hist_fin_r,
//             hist_rst_r: conn.hist_rst_r,
//             orig_nb_pkts: conn.orig_nb_pkts,
//             orig_nb_malformed_pkts: conn.orig_nb_malformed_pkts,
//             orig_nb_late_start_pkts: conn.orig_nb_late_start_pkts,
//             orig_nb_pkt_bytes: conn.orig_nb_pkt_bytes,
//             orig_nb_payload_bytes: conn.orig_nb_payload_bytes,
//             orig_max_simult_gaps: conn.orig_max_simult_gaps,
//             orig_content_gaps: conn.orig_content_gaps,
//             orig_missed_bytes: conn.orig_missed_bytes,
//             orig_mean_pkts_to_fill: conn.orig_mean_pkts_to_fill,
//             orig_median_pkts_to_fill: conn.orig_median_pkts_to_fill,
//             resp_nb_pkts: conn.resp_nb_pkts,
//             resp_nb_malformed_pkts: conn.resp_nb_malformed_pkts,
//             resp_nb_late_start_pkts: conn.resp_nb_late_start_pkts,
//             resp_nb_pkt_bytes: conn.resp_nb_pkt_bytes,
//             resp_nb_payload_bytes: conn.resp_nb_payload_bytes,
//             resp_max_simult_gaps: conn.resp_max_simult_gaps,
//             resp_content_gaps: conn.resp_content_gaps,
//             resp_missed_bytes: conn.resp_missed_bytes,
//             resp_mean_pkts_to_fill: conn.resp_mean_pkts_to_fill,
//             resp_median_pkts_to_fill: conn.resp_median_pkts_to_fill,
//             orig_iat_mean: conn.orig_iat_mean,
//             orig_iat_median: conn.orig_iat_median,
//             orig_iat_min: conn.orig_iat_min,
//             orig_iat_max: conn.orig_iat_max,
//             orig_iat_std: conn.orig_iat_std,
//             resp_iat_mean: conn.resp_iat_mean,
//             resp_iat_median: conn.resp_iat_median,
//             resp_iat_min: conn.resp_iat_min,
//             resp_iat_max: conn.resp_iat_max,
//             resp_iat_std: conn.resp_iat_std,
//             final_total_payload_bytes: conn.final_total_payload_bytes,
//             final_duration_ms: conn.final_duration_ms,
//             query_num_questions: dns.query_num_questions,
//             query_recursion_desired: dns.query_recursion_desired,
//             has_query: dns.has_query,
//             has_response: dns.has_response,
//             response_code: dns.response_code,
//             response_authoritative: dns.response_authoritative,
//             response_recursion_available: dns.response_recursion_available,
//             response_num_answers: dns.response_num_answers,
//             response_num_nameservers: dns.response_num_nameservers,
//             response_num_additional: dns.response_num_additional,
//             answer_num_a: dns.answer_num_a,
//             answer_num_aaaa: dns.answer_num_aaaa,
//             answer_num_cname: dns.answer_num_cname,
//             answer_num_mx: dns.answer_num_mx,
//             answer_num_ns: dns.answer_num_ns,
//             answer_num_ptr: dns.answer_num_ptr,
//             answer_num_soa: dns.answer_num_soa,
//             answer_num_srv: dns.answer_num_srv,
//             answer_num_txt: dns.answer_num_txt,
//             answer_num_unknown: dns.answer_num_unknown,
//             ns_num_ns: dns.ns_num_ns,
//             ns_num_soa: dns.ns_num_soa,
//             ns_num_other: dns.ns_num_other,
//             additional_num_a: dns.additional_num_a,
//             additional_num_aaaa: dns.additional_num_aaaa,
//             additional_num_other: dns.additional_num_other,
//         }
//     }
// }