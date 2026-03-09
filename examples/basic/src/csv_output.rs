use crate::flow_features::FlowFeatures;
use array_init::array_init;
use csv::Writer;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use retina_core::CoreId;

const NUM_CORES: usize = 16;
const ARR_LEN: usize = NUM_CORES + 1;

/// Per-core CSV writer managers
struct CSVWriters {
    prefix: &'static str,
    writers: OnceLock<[AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN]>,
}

impl CSVWriters {
    const fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            writers: OnceLock::new(),
        }
    }

    fn init(&self) -> &[AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN] {
        self.writers.get_or_init(|| {
            let mut ptrs = vec![];
            for core in 0..ARR_LEN {
                let path = format!("{}{}.csv", self.prefix, core);
                let file = File::create(&path).unwrap();
                let writer = csv::WriterBuilder::new()
                    .has_headers(false)
                    .from_writer(BufWriter::new(file));
                ptrs.push(Box::into_raw(Box::new(writer)));
            }
            array_init(|i| AtomicPtr::new(ptrs[i]))
        })
    }

    fn write_row<T: Serialize>(&self, row: &T, core: &CoreId) {
        let writers = self.init();
        let ptr = writers[core.raw() as usize].load(Ordering::Relaxed);
        let writer = unsafe { &mut *ptr };
        writer.serialize(row).unwrap();
    }

    fn flush_and_combine(&self, outfile: &str) {
        println!("Combining results from {} cores into {}...", ARR_LEN, outfile);
        let mut out = BufWriter::new(File::create(outfile).unwrap());
        out.write_all(FlowFeatures::HEADER.as_bytes()).unwrap();

        let writers = self.init();
        for core in 0..ARR_LEN {
            let ptr = writers[core].load(Ordering::Relaxed);
            let writer = unsafe { &mut *ptr };
            writer.flush().unwrap();

            let path = format!("{}{}.csv", self.prefix, core);
            std::io::copy(&mut File::open(&path).unwrap(), &mut out).unwrap();
            std::fs::remove_file(&path).unwrap();
        }

        println!("Done. Written to {}", outfile);
    }
}

static REGULAR: CSVWriters = CSVWriters::new("flow_features_");
static TLS: CSVWriters = CSVWriters::new("flow_features_tls_");

/// Public API
pub fn write(features: &FlowFeatures, core: &CoreId) {
    REGULAR.write_row(features, core)
}

pub fn write_tls(features: &FlowFeatures, core: &CoreId) {
    TLS.write_row(features, core)
}

pub fn combine() {
    REGULAR.flush_and_combine("flow_features.csv");
    TLS.flush_and_combine("flow_features_tls.csv");
}