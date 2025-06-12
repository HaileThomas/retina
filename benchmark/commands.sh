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
    echo "Running with Queue capacity = $qs"
    benchmark_stats "$target" --queue-size="$qs" "$@"
    echo "----------------------------------------"
  done
}

benchmark_profile_callbacks() {
  local target="$1"
  shift

  local output_dir="./benchmark/output"
  rm -rf "$output_dir" && mkdir -p "$output_dir"
  
  echo "Running perf record on target: $target"
  
  sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" RUST_LOG=error \
    perf record \
    --call-graph lbr \
    -F 10000 \
    -g \
    --output="$output_dir/benchmark_profile.perf.data" \
    ./target/debug/"$target" "$@"

  sudo chown "$USER:$USER" "$output_dir/benchmark_profile.perf.data" 2>/dev/null || true

  perf report \
    --input="$output_dir/benchmark_profile.perf.data" \
    --stdio \
    --sort=overhead,symbol \
    --call-graph=graph,0.5,caller \
    > "$output_dir/benchmark_profile_report.txt"

  echo "Report saved to benchmark_profile_report.txt"
}

benchmark_profile_cores() {
  local target="$1"
  shift

  local output_dir="./benchmark/output"
  rm -rf "$output_dir" && mkdir -p "$output_dir"

  # Define cores here
  local CALLBACK_CORE=1
  local PROCESSING_CORE=2

  local callback_core="${CALLBACK_CORE:?CALLBACK_CORE not set}"
  local processing_core="${PROCESSING_CORE:?PROCESSING_CORE not set}"

  echo "Profiling callback core $callback_core and processing core $processing_core..."

  sudo perf record -C "$callback_core" --call-graph lbr -F 10000 \
    -o "$output_dir/callback_core${callback_core}.perf.data" & callback_pid=$!
  sudo perf record -C "$processing_core" --call-graph lbr -F 10000 \
    -o "$output_dir/processing_core${processing_core}.perf.data" & processing_pid=$!
  sleep 1  # allow perf to initialize

  env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=debug ./target/debug/"$target" "$@"

  sudo kill -INT "$callback_pid" "$processing_pid" 2>/dev/null || true
  wait "$callback_pid" "$processing_pid" 2>/dev/null || true

  sudo chown "$USER:$USER" "$output_dir/callback_core${callback_core}.perf.data" 2>/dev/null || true
  sudo chown "$USER:$USER" "$output_dir/processing_core${processing_core}.perf.data" 2>/dev/null || true

  perf report -f -i "$output_dir/callback_core${callback_core}.perf.data" --stdio > \
    "$output_dir/callback_core${callback_core}_report.txt"
  perf report -f -i "$output_dir/processing_core${processing_core}.perf.data" --stdio > \
    "$output_dir/processing_core${processing_core}_report.txt"

  sudo chown -R "$USER:$USER" "$output_dir"
  echo "Reports: callback_core${callback_core}_report.txt, processing_core${processing_core}_report.txt"
}

