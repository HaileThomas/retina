use std::sync::{Arc, Mutex};
use std::time::Instant; 

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub subscriptions_processed: u64,
    pub subscriptions_dropped: u64,
    pub latency_ms: f64,
}

#[derive(Debug)]
pub struct BenchmarkManager {
    results: Arc<Mutex<Metrics>>,
}

impl BenchmarkManager {
    pub fn new() -> Self {
        Self {
            results: Arc::new(Mutex::new(Metrics::default())),
        }
    }

    pub fn increment_processed_subscriptions(&self) {
        let mut results = self.results.lock().unwrap();
        results.subscriptions_processed += 1;
    }

    pub fn increment_dropped_subscriptions(&self) {
        let mut results = self.results.lock().unwrap();
        results.subscriptions_dropped += 1;
    }

    pub fn calculate_latency(&self, start: Instant) {
        let mut results = self.results.lock().unwrap(); 

        let elapsed_time = start.elapsed().as_secs_f64() * 1000.0; 
        let count = results.subscriptions_processed as f64; 

        results.latency_ms = ((results.latency_ms * (count - 1.0)) + elapsed_time) / count; 
    }

    pub fn print_results(&self) {
        let metrics = self.results.lock().unwrap();
        
        println!("Subscriptions Processed: {}", metrics.subscriptions_processed);
        println!("Subscriptions Dropped: {}", metrics.subscriptions_dropped);
        println!("Subscription Processing Latency: {:.2} ms", metrics.latency_ms);
    }
}
