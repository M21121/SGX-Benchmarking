#!/bin/bash

# benchmark.sh - Enhanced script to benchmark SGX application performance
# Measures execution time for ecalls, ocalls, pingpongs, and file operations
# Uses the same number of iterations for all tests for consistent comparison

# Set the number of iterations (can be overridden with command line args)
ITERATIONS=10000      # Default number of iterations for all tests
TRIALS=3              # Number of trials for each benchmark
FILE_SIZE_1=1         # Size in KB for the first test file
FILE_SIZE_2=100       # Size in KB for the second test file

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Parse command line arguments
while getopts "i:t:h" opt; do
  case $opt in
    i) ITERATIONS=$OPTARG ;;
    t) TRIALS=$OPTARG ;;
    h)
      echo "Usage: $0 [-i iterations] [-t trials]"
      echo "  -i: Number of iterations for all tests (default: 10000)"
      echo "  -t: Number of trials for each test (default: 3)"
      exit 0
      ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}======================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}======================================${NC}"
}

# Function to run a benchmark and display results
run_benchmark() {
    local test_type=$1
    local desc=$2
    local extra_args=${3:-""}     # Extra arguments for the command

    print_header "Benchmarking $desc ($ITERATIONS iterations)"

    # Run the benchmark multiple times and take the average
    echo "Running $TRIALS trials..."

    total_real=0
    total_user=0
    total_sys=0

    # Arrays to store individual trial results
    declare -a real_times
    declare -a user_times
    declare -a sys_times

    for i in $(seq 1 $TRIALS); do
        echo -e "\nTrial $i:"

        # Use time command with format that's easy to parse
        result=$( { /usr/bin/time -f "real %e\nuser %U\nsys %S" ./app --test $test_type --iterations $ITERATIONS $extra_args; } 2>&1 )

        # Extract timing information
        real=$(echo "$result" | grep "real" | awk '{print $2}')
        user=$(echo "$result" | grep "user" | awk '{print $2}')
        sys=$(echo "$result" | grep "sys" | awk '{print $2}')

        # Store in arrays
        real_times[$i]=$real
        user_times[$i]=$user
        sys_times[$i]=$sys

        # Display results for this trial
        echo "  Real time: ${real}s"
        echo "  User time: ${user}s"
        echo "  Sys time:  ${sys}s"

        # Add to totals
        total_real=$(echo "$total_real + $real" | bc)
        total_user=$(echo "$total_user + $user" | bc)
        total_sys=$(echo "$total_sys + $sys" | bc)
    done

    # Calculate averages
    avg_real=$(echo "scale=6; $total_real / $TRIALS" | bc)
    avg_user=$(echo "scale=6; $total_user / $TRIALS" | bc)
    avg_sys=$(echo "scale=6; $total_sys / $TRIALS" | bc)

    # Calculate standard deviation for real time
    sum_squared_diff=0
    for i in $(seq 1 $TRIALS); do
        diff=$(echo "${real_times[$i]} - $avg_real" | bc)
        squared_diff=$(echo "$diff * $diff" | bc)
        sum_squared_diff=$(echo "$sum_squared_diff + $squared_diff" | bc)
    done
    variance=$(echo "scale=6; $sum_squared_diff / $TRIALS" | bc)
    stddev=$(echo "scale=6; sqrt($variance)" | bc)

    # Calculate coefficient of variation (CV) as percentage
    cv=$(echo "scale=2; 100 * $stddev / $avg_real" | bc)

    # Calculate operations per second
    ops_per_sec=$(echo "scale=2; $ITERATIONS / $avg_real" | bc)

    # Display average results
    echo -e "\n${GREEN}Average Results:${NC}"
    echo "  Real time: ${avg_real}s (±${stddev}s, CV: ${cv}%)"
    echo "  User time: ${avg_user}s"
    echo "  Sys time:  ${avg_sys}s"
    echo -e "${GREEN}Performance: $ops_per_sec operations/second${NC}"

    # Calculate time per operation in microseconds
    time_per_op=$(echo "scale=2; $avg_real * 1000000 / $ITERATIONS" | bc)
    echo -e "${GREEN}Time per operation: $time_per_op microseconds${NC}"

    # Save results to CSV with a clean description (replace commas with spaces)
    clean_desc=$(echo "$desc" | tr ',' ' ')
    echo "$test_type,$clean_desc,$ITERATIONS,$avg_real,$avg_user,$avg_sys,$stddev,$cv,$ops_per_sec,$time_per_op" >> benchmark_results.csv
}

# Create test files of different sizes
create_test_file() {
    local size_kb=$1
    local filename="file_${size_kb}kb.txt"

    # For O_DIRECT, file size should be a multiple of block size (typically 512 bytes)
    local block_size=4096  # 4KB blocks
    local blocks=$(( ($size_kb * 1024 + $block_size - 1) / $block_size ))
    local actual_size=$(( $blocks * $block_size / 1024 ))

    echo "Creating test file: $filename (requested: $size_kb KB, actual: $actual_size KB)"

    # Use dd with block size matching O_DIRECT requirements
    dd if=/dev/urandom of="$filename" bs=$block_size count=$blocks status=none 2>/dev/null

    echo "Created $filename: $(du -h $filename | cut -f1)"

    # Sync to ensure file is written to disk
    sync

    echo "$filename"  # Return the filename
}

# Check if the app exists
if [ ! -f "./app" ]; then
    echo -e "${RED}Error: 'app' executable not found. Please compile the application first.${NC}"
    exit 1
fi

# Create results CSV file with header
echo "test_type,description,iterations,avg_real_time,avg_user_time,avg_sys_time,stddev,cv_percent,ops_per_second,time_per_op_us" > benchmark_results.csv

# Print system information
print_header "System Information"
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo "CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d ':' -f2 | sed 's/^[ \t]*//')"
echo "CPU Cores: $(grep -c processor /proc/cpuinfo)"
echo "Memory: $(free -h | grep Mem | awk '{print $2}')"

# Check for SGX support
if [ -c /dev/isgx ] || [ -c /dev/sgx ]; then
    echo -e "${GREEN}SGX device found: SGX is supported${NC}"
else
    echo -e "${YELLOW}Warning: No SGX device found. Running in simulation mode?${NC}"
fi

# Create test files
print_header "Creating Test Files"
file1=$(create_test_file $FILE_SIZE_1)
file2=$(create_test_file $FILE_SIZE_2)

# Print benchmark configuration
print_header "Benchmark Configuration"
echo "Iterations per test: $ITERATIONS"
echo "Trials per test: $TRIALS"
echo "Test files: $file1 ($FILE_SIZE_1 KB), $file2 ($FILE_SIZE_2 KB)"

# Run all benchmarks with the same number of iterations
run_benchmark "init" "Enclave Initialization Only"
run_benchmark "ecall" "Empty ECALL"
run_benchmark "ocall" "Empty OCALL"
run_benchmark "pingpong" "Ping-Pong (ECALL-OCALL round-trip)"
run_benchmark "fileread" "Single Read (${FILE_SIZE_1}KB File)" "--file $file1"
run_benchmark "fileread" "Single Read (${FILE_SIZE_2}KB File)" "--file $file2"
run_benchmark "securefileread" "Secure Read (${FILE_SIZE_1}KB File)" "--file $file1"
run_benchmark "directfileread" "Direct I/O Read (${FILE_SIZE_1}KB File)" "--file $file1"
run_benchmark "directfileread" "Direct I/O Read (${FILE_SIZE_2}KB File)" "--file $file2"

# Generate summary
print_header "Benchmark Summary"
echo "Results saved to benchmark_results.csv"

# Display CSV data in a readable format
echo -e "\nOperation         Description                Time/op (μs)    Ops/second    Variation"
echo "--------------------------------------------------------------------------------"
while IFS=, read -r test desc iterations real user sys stddev cv ops_per_sec time_per_op; do
    if [ "$test" != "test_type" ]; then
        # Format the output with proper spacing
        printf "%-15s  %-25s  %8.2f μs     %10.2f/s    ±%5.2f%%\n" \
               "$test" "$desc" "$time_per_op" "$ops_per_sec" "$cv"
    fi
done < benchmark_results.csv

# Create a simple chart using ASCII art
print_header "Performance Comparison (time per operation)"
echo "Lower is better:"
echo ""

# Find the maximum time for scaling
max_time=$(awk -F, 'NR>1 {if($10>max) max=$10} END {print max}' benchmark_results.csv)
scale_factor=$(echo "scale=0; 50 / $max_time" | bc)

# Print the chart
while IFS=, read -r test desc iterations real user sys stddev cv ops_per_sec time_per_op; do
    if [ "$test" != "test_type" ]; then
        # Calculate bar length
        bar_len=$(echo "scale=0; $time_per_op * $scale_factor / 1" | bc)

        # Print the bar
        printf "%-15s [" "$test"
        for ((i=0; i<bar_len; i++)); do
            printf "#"
        done
        printf "%*s] %8.2f μs\n" $((50-bar_len)) "" "$time_per_op"
    fi
done < benchmark_results.csv

echo -e "\n${GREEN}Benchmark completed successfully${NC}"

# Clean up test files (optional)
read -p "Remove test files? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_header "Cleaning Up"
    rm -f "$file1" "$file2"
    echo "Test files removed"
fi
