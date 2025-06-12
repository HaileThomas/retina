benchmark_stats() {
  local target="$1"
  shift

  sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=debug \
    perf stat -e stalled-cycles-frontend,stalled-cycles-backend,cache-misses,major-faults \
    ./target/debug/"$target" "$@"
}

benchmark_stats_sweep() {
  local target="$1"
  shift

  local queue_sizes=(64 128 256 512 1024 2048 4096 8192 16384 32768)

  for qs in "${queue_sizes[@]}"; do
    echo "Running with Queue capacity =$qs"
    benchmark_stats "$target" --queue-size="$qs" "$@"
    echo "----------------------------------------"
  done
}

