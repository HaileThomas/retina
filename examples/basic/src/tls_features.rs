use retina_datatypes::TlsHandshake;
use serde::Serialize;
use std::net::IpAddr;
use crate::hash_utils::hash_ip;

#[derive(Clone, Debug, Serialize)]
pub struct TlsFeatures {
    pub client_ip_hash:               u64,  // hash of TLS client IP
    pub server_ip_hash:               u64,  // hash of TLS server IP

    // --- ClientHello ---
    pub has_client_hello:             u8,   // 1 if a ClientHello was observed
    pub client_version:               u16,  // legacy record version from ClientHello
    pub client_num_supported_groups:  u16,  // number of named groups in supported_groups extension
    pub client_num_sig_algs:          u16,  // number of signature algorithms advertised
    pub client_num_alpn_protocols:    u16,  // number of ALPN protocols advertised
    pub client_num_key_shares:        u16,  // number of key share entries (TLS 1.3)
    pub client_num_supported_vers:    u16,  // number of supported_versions entries (TLS 1.3)
    pub client_has_sni:               u8,   // 1 if SNI extension is present
    pub client_sni_len:               u16,  // byte length of the SNI hostname, 0 if absent
    pub client_has_session_id:        u8,   // 1 if session_id is non-empty (session resumption hint)
    pub client_session_id_len:        u8,   // length of session_id in bytes (0–32)
    pub client_has_compression:       u8,   // 1 if any non-null compression method is offered
    pub client_has_alpn:              u8,   // 1 if ALPN extension is present
    pub client_has_key_share:         u8,   // 1 if key_share extension is present (TLS 1.3)
    pub client_has_supported_vers:    u8,   // 1 if supported_versions extension is present (TLS 1.3)

    // --- ServerHello ---
    pub has_server_hello:             u8,   // 1 if a ServerHello was observed
    pub server_version:               u16,  // legacy record version from ServerHello
    pub server_cipher_suite:          u16,  // chosen cipher suite ID
    pub server_compression_alg:       u8,   // chosen compression method (0 = null)
    pub server_has_alpn:              u8,   // 1 if server sent ALPN extension
    pub server_has_key_share:         u8,   // 1 if server sent key_share extension (TLS 1.3)
    pub server_has_selected_vers:     u8,   // 1 if server sent supported_versions extension (TLS 1.3)

    // --- Certificates ---
    pub num_server_certs:             u16,  // number of certificates in the server certificate chain
    pub num_client_certs:             u16,  // number of certificates in the client certificate chain
    pub server_cert0_len:             u32,  // raw byte length of the leaf server certificate, 0 if absent
    pub server_cert1_len:             u32,  // raw byte length of the first intermediate cert, 0 if absent

    // --- Key exchange ---
    pub has_server_kex:               u8,   // 1 if ServerKeyExchange was observed (TLS 1.2-)
    pub has_client_kex:               u8,   // 1 if ClientKeyExchange was observed (TLS 1.2-)
    pub kex_type:                     u8,   // 0=none/unknown 1=ECDH 2=DH 3=RSA
}

impl TlsFeatures {
    pub fn from_tls(tls: &TlsHandshake, client_ip: IpAddr, server_ip: IpAddr) -> Option<Self> {
        if tls.client_hello.is_none() && tls.server_hello.is_none() {
            return None;
        }

        let client_ip_hash = hash_ip(client_ip);
        let server_ip_hash = hash_ip(server_ip);

        // --- ClientHello fields ---
        let (
            has_client_hello,
            client_version,
            client_num_supported_groups,
            client_num_sig_algs,
            client_num_alpn_protocols,
            client_num_key_shares,
            client_num_supported_vers,
            client_has_sni,
            client_sni_len,
            client_has_session_id,
            client_session_id_len,
            client_has_compression,
            client_has_alpn,
            client_has_key_share,
            client_has_supported_vers,
        ) = if let Some(ch) = &tls.client_hello {
            let sni_len = ch.server_name.as_deref().map(|s| s.len() as u16).unwrap_or(0);
            (
                1u8,
                ch.version.0,
                ch.supported_groups.len() as u16,
                ch.signature_algs.len() as u16,
                ch.alpn_protocols.len() as u16,
                ch.key_shares.len() as u16,
                ch.supported_versions.len() as u16,
                ch.server_name.is_some() as u8,
                sni_len,
                (!ch.session_id.is_empty()) as u8,
                ch.session_id.len() as u8,
                ch.compression_algs.iter().any(|c| c.0 != 0) as u8,
                (!ch.alpn_protocols.is_empty()) as u8,
                (!ch.key_shares.is_empty()) as u8,
                (!ch.supported_versions.is_empty()) as u8,
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        };

        // --- ServerHello fields ---
        let (
            has_server_hello,
            server_version,
            server_cipher_suite,
            server_compression_alg,
            server_has_alpn,
            server_has_key_share,
            server_has_selected_vers,
        ) = if let Some(sh) = &tls.server_hello {
            (
                1u8,
                sh.version.0,
                sh.cipher_suite.0,
                sh.compression_alg.0,
                sh.alpn_protocol.is_some() as u8,
                sh.key_share.is_some() as u8,
                sh.selected_version.is_some() as u8,
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0)
        };

        // --- Certificate fields ---
        let num_server_certs = tls.server_certificates.len() as u16;
        let num_client_certs = tls.client_certificates.len() as u16;
        let server_cert0_len = tls.server_certificates.first().map(|c| c.raw.len() as u32).unwrap_or(0);
        let server_cert1_len = tls.server_certificates.get(1).map(|c| c.raw.len() as u32).unwrap_or(0);

        // --- Key exchange fields ---
        use retina_core::protocols::stream::tls::{ClientKeyExchange, ServerKeyExchange};
        let has_server_kex = tls.server_key_exchange.is_some() as u8;
        let has_client_kex = tls.client_key_exchange.is_some() as u8;
        let kex_type: u8 = match &tls.server_key_exchange {
            Some(ServerKeyExchange::Ecdh(_)) => 1,
            Some(ServerKeyExchange::Dh(_))   => 2,
            Some(ServerKeyExchange::Rsa(_))  => 3,
            _ => match &tls.client_key_exchange {
                Some(ClientKeyExchange::Ecdh(_)) => 1,
                Some(ClientKeyExchange::Dh(_))   => 2,
                Some(ClientKeyExchange::Rsa(_))  => 3,
                _ => 0,
            },
        };

        Some(Self {
            client_ip_hash,
            server_ip_hash,
            has_client_hello,
            client_version,
            client_num_supported_groups,
            client_num_sig_algs,
            client_num_alpn_protocols,
            client_num_key_shares,
            client_num_supported_vers,
            client_has_sni,
            client_sni_len,
            client_has_session_id,
            client_session_id_len,
            client_has_compression,
            client_has_alpn,
            client_has_key_share,
            client_has_supported_vers,
            has_server_hello,
            server_version,
            server_cipher_suite,
            server_compression_alg,
            server_has_alpn,
            server_has_key_share,
            server_has_selected_vers,
            num_server_certs,
            num_client_certs,
            server_cert0_len,
            server_cert1_len,
            has_server_kex,
            has_client_kex,
            kex_type,
        })
    }
}

// #[derive(Serialize)]
// pub struct TlsConnFeatures {
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
//     // TlsFeatures fields
//     pub has_client_hello: u8,
//     pub client_version: u16,
//     pub client_num_supported_groups: u16,
//     pub client_num_sig_algs: u16,
//     pub client_num_alpn_protocols: u16,
//     pub client_num_key_shares: u16,
//     pub client_num_supported_vers: u16,
//     pub client_has_sni: u8,
//     pub client_sni_len: u16,
//     pub client_has_session_id: u8,
//     pub client_session_id_len: u8,
//     pub client_has_compression: u8,
//     pub client_has_alpn: u8,
//     pub client_has_key_share: u8,
//     pub client_has_supported_vers: u8,
//     pub has_server_hello: u8,
//     pub server_version: u16,
//     pub server_cipher_suite: u16,
//     pub server_compression_alg: u8,
//     pub server_has_alpn: u8,
//     pub server_has_key_share: u8,
//     pub server_has_selected_vers: u8,
//     pub num_server_certs: u16,
//     pub num_client_certs: u16,
//     pub server_cert0_len: u32,
//     pub server_cert1_len: u32,
//     pub has_server_kex: u8,
//     pub has_client_kex: u8,
//     pub kex_type: u8,
// }

// impl TlsConnFeatures {
//     pub fn new(conn: ConnFeatures, tls: TlsFeatures) -> Self {
//         Self {
//             src_ip_subn:               conn.src_ip_subn,
//             dst_ip_subn:               conn.dst_ip_subn,
//             src_port:                  conn.src_port,
//             dst_port:                  conn.dst_port,
//             protocol:                  conn.protocol,
//             duration_ms:               conn.duration_ms,
//             max_inactivity_ms:         conn.max_inactivity_ms,
//             time_to_second_pkt_ms:     conn.time_to_second_pkt_ms,
//             hist_syn:                  conn.hist_syn,
//             hist_synack:               conn.hist_synack,
//             hist_ack:                  conn.hist_ack,
//             hist_data:                 conn.hist_data,
//             hist_fin:                  conn.hist_fin,
//             hist_rst:                  conn.hist_rst,
//             hist_syn_r:                conn.hist_syn_r,
//             hist_synack_r:             conn.hist_synack_r,
//             hist_ack_r:                conn.hist_ack_r,
//             hist_data_r:               conn.hist_data_r,
//             hist_fin_r:                conn.hist_fin_r,
//             hist_rst_r:                conn.hist_rst_r,
//             orig_nb_pkts:              conn.orig_nb_pkts,
//             orig_nb_malformed_pkts:    conn.orig_nb_malformed_pkts,
//             orig_nb_late_start_pkts:   conn.orig_nb_late_start_pkts,
//             orig_nb_pkt_bytes:         conn.orig_nb_pkt_bytes,
//             orig_nb_payload_bytes:     conn.orig_nb_payload_bytes,
//             orig_max_simult_gaps:      conn.orig_max_simult_gaps,
//             orig_content_gaps:         conn.orig_content_gaps,
//             orig_missed_bytes:         conn.orig_missed_bytes,
//             orig_mean_pkts_to_fill:    conn.orig_mean_pkts_to_fill,
//             orig_median_pkts_to_fill:  conn.orig_median_pkts_to_fill,
//             resp_nb_pkts:              conn.resp_nb_pkts,
//             resp_nb_malformed_pkts:    conn.resp_nb_malformed_pkts,
//             resp_nb_late_start_pkts:   conn.resp_nb_late_start_pkts,
//             resp_nb_pkt_bytes:         conn.resp_nb_pkt_bytes,
//             resp_nb_payload_bytes:     conn.resp_nb_payload_bytes,
//             resp_max_simult_gaps:      conn.resp_max_simult_gaps,
//             resp_content_gaps:         conn.resp_content_gaps,
//             resp_missed_bytes:         conn.resp_missed_bytes,
//             resp_mean_pkts_to_fill:    conn.resp_mean_pkts_to_fill,
//             resp_median_pkts_to_fill:  conn.resp_median_pkts_to_fill,
//             orig_iat_mean:             conn.orig_iat_mean,
//             orig_iat_median:           conn.orig_iat_median,
//             orig_iat_min:              conn.orig_iat_min,
//             orig_iat_max:              conn.orig_iat_max,
//             orig_iat_std:              conn.orig_iat_std,
//             resp_iat_mean:             conn.resp_iat_mean,
//             resp_iat_median:           conn.resp_iat_median,
//             resp_iat_min:              conn.resp_iat_min,
//             resp_iat_max:              conn.resp_iat_max,
//             resp_iat_std:              conn.resp_iat_std,
//             final_total_payload_bytes: conn.final_total_payload_bytes,
//             final_duration_ms:         conn.final_duration_ms,
//             has_client_hello:          tls.has_client_hello,
//             client_version:            tls.client_version,
//             client_num_supported_groups: tls.client_num_supported_groups,
//             client_num_sig_algs:       tls.client_num_sig_algs,
//             client_num_alpn_protocols: tls.client_num_alpn_protocols,
//             client_num_key_shares:     tls.client_num_key_shares,
//             client_num_supported_vers: tls.client_num_supported_vers,
//             client_has_sni:            tls.client_has_sni,
//             client_sni_len:            tls.client_sni_len,
//             client_has_session_id:     tls.client_has_session_id,
//             client_session_id_len:     tls.client_session_id_len,
//             client_has_compression:    tls.client_has_compression,
//             client_has_alpn:           tls.client_has_alpn,
//             client_has_key_share:      tls.client_has_key_share,
//             client_has_supported_vers: tls.client_has_supported_vers,
//             has_server_hello:          tls.has_server_hello,
//             server_version:            tls.server_version,
//             server_cipher_suite:       tls.server_cipher_suite,
//             server_compression_alg:    tls.server_compression_alg,
//             server_has_alpn:           tls.server_has_alpn,
//             server_has_key_share:      tls.server_has_key_share,
//             server_has_selected_vers:  tls.server_has_selected_vers,
//             num_server_certs:          tls.num_server_certs,
//             num_client_certs:          tls.num_client_certs,
//             server_cert0_len:          tls.server_cert0_len,
//             server_cert1_len:          tls.server_cert1_len,
//             has_server_kex:            tls.has_server_kex,
//             has_client_kex:            tls.has_client_kex,
//             kex_type:                  tls.kex_type,
//         }
//     }
// }