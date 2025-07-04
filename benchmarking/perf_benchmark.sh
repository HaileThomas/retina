#!/bin/bash
trap 'print_error "An error occurred. Exiting script safely."' ERR
source ./benchmarking/logging.sh

run_perf_stat() {
    local output_file="$RESULTS_DIR/perf_stat.txt"
    local perf_events="cycles,instructions,cache-references,cache-misses,stalled-cycles-frontend,stalled-cycles-backend,major-faults,minor-faults,page-faults"
    
    print_status "Running performance statistics: $output_file"
    
    sudo perf stat \
        -e "$perf_events" \
        -o "$output_file" \
        env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" RUST_LOG=error "$BINARY_PATH" 2>&1 || {
            print_error "perf stat failed"
            return 1
        }
        
    print_status "Completed: $output_file"
}

main() {
    local binary_name="$1"
    
    if [ -z "$binary_name" ]; then
        print_error "Usage: $0 <binary_name>"
        return 1
    fi
    
    BINARY_PATH="./target/release/${binary_name}"
    
    if [ ! -f "$BINARY_PATH" ]; then
        print_error "Binary not found: $BINARY_PATH"
        return 1
    fi
    
    RESULTS_DIR="./benchmarking/results/${binary_name}/stats"
    
    if [ -d "$RESULTS_DIR" ]; then
        rm -rf "$RESULTS_DIR"
    fi
    
    mkdir -p "$RESULTS_DIR"
    print_status "Results directory: $RESULTS_DIR"
    
    if ! sudo perf stat -e cycles true &>/dev/null; then
        print_error "Perf not working. Try: sudo sysctl kernel.perf_event_paranoid=1"
        return 1
    fi
    
    print_status "Starting benchmark: $binary_name"
    run_perf_stat
    print_status "Benchmark complete: $RESULTS_DIR"
}

main "$@"
