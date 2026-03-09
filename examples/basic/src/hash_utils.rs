use std::net::IpAddr;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const HASH_SALT: u64 = 0x9e3779b97f4a7c15;

pub fn hash_ip(ip: IpAddr) -> u64 {
    let mut h = DefaultHasher::new();
    HASH_SALT.hash(&mut h);
    ip.hash(&mut h);
    h.finish()
}