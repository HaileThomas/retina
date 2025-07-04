#!/bin/bash
trap 'print_error "An error occurred. Exiting script safely."' ERR
source ./benchmarking/logging.sh

perf_record_and_report() {
    local cores="$1"
    local output_file="$RESULTS_DIR/perf_record.data"
    
    if [ -n "$cores" ]; then
        print_status "Recording system-wide, filtering to cores: $cores"
        
        if ! sudo perf record \
            -a \
            -C "$cores" \
            --call-graph lbr \
            -F 10000 \
            -g \
            -o "$output_file" \
            env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" RUST_LOG=error "$BINARY_PATH" 2>&1; then
            print_error "Perf record failed on filtered cores"
            return 1
        fi
    else
        print_status "Recording process-specific data: $output_file"
        
        if ! sudo perf record \
            --call-graph lbr \
            -F 10000 \
            -g \
            -o "$output_file" \
            env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" RUST_LOG=error "$BINARY_PATH" 2>&1; then
            print_error "Perf record failed"
            return 1
        fi
    fi
    
    print_status "Generating report"
    if ! sudo perf report -i "$output_file" --sort=overhead,symbol; then
        print_warning "Report generation failed"
    fi
    
    print_status "Data recorded: $output_file"
}

main() {
    local binary_name="$1"
    local cpu_cores="$2"
    
    if [ -z "$binary_name" ]; then
        print_error "Usage: $0 <binary_name> [cpu_cores]"
        return 1
    fi
    
    if [ -n "$cpu_cores" ] && ! echo "$cpu_cores" | grep -qE '^[0-9]+(,[0-9]+)*$'; then
        print_error "Invalid CPU cores format: $cpu_cores"
        return 1
    fi
    
    BINARY_PATH="./target/release/${binary_name}"
    
    if [ ! -f "$BINARY_PATH" ]; then
        print_error "Binary not found: $BINARY_PATH"
        return 1
    fi
    
    RESULTS_DIR="./benchmarking/results/${binary_name}/profile"
    
    if [ -d "$RESULTS_DIR" ]; then
        rm -rf "$RESULTS_DIR"
    fi
    
    mkdir -p "$RESULTS_DIR"
    print_status "Results directory: $RESULTS_DIR"
    
    if ! sudo perf record --help >/dev/null 2>&1; then
        print_error "Perf record not available"
        return 1
    fi
    
    print_status "Starting profiling: $binary_name"
    perf_record_and_report "$cpu_cores"
    print_status "Profiling complete: $RESULTS_DIR"
}

main "$@"
