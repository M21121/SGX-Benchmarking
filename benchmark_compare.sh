#!/bin/bash

# benchmark_compare.sh - Script to benchmark and compare SGX applications with and without mitigations
# Measures execution time for both versions and generates a comparison report

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
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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
    local app_binary=$1
    local test_type=$2
    local desc=$3
    local extra_args=${4:-""}     # Extra arguments for the command
    local result_file=$5          # CSV file to save results

    print_header "Benchmarking $desc ($ITERATIONS iterations) with $app_binary"

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
        result=$( { /usr/bin/time -f "real %e\nuser %U\nsys %S" ./$app_binary --test $test_type --iterations $ITERATIONS $extra_args; } 2>&1 )

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
    echo "$app_binary,$test_type,$clean_desc,$ITERATIONS,$avg_real,$avg_user,$avg_sys,$stddev,$cv,$ops_per_sec,$time_per_op" >> $result_file
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

# Check if both app binaries exist
if [ ! -f "./app" ]; then
    echo -e "${RED}Error: 'app' executable not found. Please compile the application first.${NC}"
    exit 1
fi

if [ ! -f "./app_no_mitigations" ]; then
    echo -e "${RED}Error: 'app_no_mitigations' executable not found. Please compile it first.${NC}"
    exit 1
fi

# Create results CSV files with headers
echo "app,test_type,description,iterations,avg_real_time,avg_user_time,avg_sys_time,stddev,cv_percent,ops_per_second,time_per_op_us" > benchmark_results_mitigated.csv
echo "app,test_type,description,iterations,avg_real_time,avg_user_time,avg_sys_time,stddev,cv_percent,ops_per_second,time_per_op_us" > benchmark_results_unmitigated.csv
echo "test_type,description,mitigated_time_us,unmitigated_time_us,overhead_percent,mitigated_ops_per_sec,unmitigated_ops_per_sec" > benchmark_comparison.csv

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

# Define the test cases
declare -a test_cases=(
    "init:Enclave Initialization Only:"
    "ecall:Empty ECALL:"
    "ocall:Empty OCALL:"
    "pingpong:Ping-Pong (ECALL-OCALL round-trip):"
    "fileread:Single Read (${FILE_SIZE_1}KB File):--file $file1"
    "fileread:Single Read (${FILE_SIZE_2}KB File):--file $file2"
    "securefileread:Secure Read (${FILE_SIZE_1}KB File):--file $file1"
    "directfileread:Direct I/O Read (${FILE_SIZE_1}KB File):--file $file1"
    "directfileread:Direct I/O Read (${FILE_SIZE_2}KB File):--file $file2"
)

# Run benchmarks for both versions
print_header "Running Benchmarks for Mitigated Version"
for test_case in "${test_cases[@]}"; do
    IFS=':' read -r test_type desc extra_args <<< "$test_case"
    run_benchmark "app" "$test_type" "$desc" "$extra_args" "benchmark_results_mitigated.csv"
done

print_header "Running Benchmarks for Unmitigated Version"
for test_case in "${test_cases[@]}"; do
    IFS=':' read -r test_type desc extra_args <<< "$test_case"
    run_benchmark "app_no_mitigations" "$test_type" "$desc" "$extra_args" "benchmark_results_unmitigated.csv"
done

# Generate comparison data
print_header "Generating Comparison Data"

# Process the results to create a comparison
while IFS=, read -r app1 test_type1 desc1 iterations1 real1 user1 sys1 stddev1 cv1 ops1 time_per_op1; do
    if [ "$app1" != "app" ]; then
        # Find matching entry in unmitigated results
        while IFS=, read -r app2 test_type2 desc2 iterations2 real2 user2 sys2 stddev2 cv2 ops2 time_per_op2; do
            if [ "$app2" != "app_no_mitigations" ] && [ "$test_type1" == "$test_type2" ] && [ "$desc1" == "$desc2" ]; then
                # Calculate overhead percentage
                overhead=$(echo "scale=2; 100 * ($time_per_op1 - $time_per_op2) / $time_per_op2" | bc)

                # Add to comparison CSV
                echo "$test_type1,$desc1,$time_per_op1,$time_per_op2,$overhead,$ops1,$ops2" >> benchmark_comparison.csv
                break
            fi
        done < benchmark_results_unmitigated.csv
    fi
done < benchmark_results_mitigated.csv

# Generate summary
print_header "Benchmark Comparison Summary"
echo "Results saved to benchmark_comparison.csv"

# Display comparison data in a readable format
echo -e "\n${CYAN}Security Overhead Comparison${NC}"
echo -e "\nOperation         Description                Mitigated   Unmitigated   Overhead"
echo "--------------------------------------------------------------------------------"
while IFS=, read -r test desc time1 time2 overhead ops1 ops2; do
    if [ "$test" != "test_type" ]; then
        # Format the output with proper spacing
        printf "%-15s  %-25s  %8.2f μs   %8.2f μs   %+6.2f%%\n" \
               "$test" "$desc" "$time1" "$time2" "$overhead"
    fi
done < benchmark_comparison.csv

# Create a side-by-side bar chart using ASCII art
print_header "Performance Comparison (time per operation)"
echo "Lower is better:"
echo ""

# Find the maximum time for scaling
max_time=$(awk -F, 'NR>1 {if($3>max) max=$3; if($4>max) max=$4} END {print max}' benchmark_comparison.csv)
scale_factor=$(echo "scale=0; 25 / $max_time" | bc)

# Print the chart
while IFS=, read -r test desc time1 time2 overhead ops1 ops2; do
    if [ "$test" != "test_type" ]; then
        # Calculate bar lengths
        bar_len1=$(echo "scale=0; $time1 * $scale_factor / 1" | bc)
        bar_len2=$(echo "scale=0; $time2 * $scale_factor / 1" | bc)

        # Print the bars side by side
        printf "%-15s " "$test"

        # Mitigated bar (cyan)
        printf "${CYAN}["
        for ((i=0; i<bar_len1; i++)); do
            printf "#"
        done
        printf "%*s]${NC} %8.2f μs" $((25-bar_len1)) "" "$time1"

        # Unmitigated bar (magenta)
        printf " ${MAGENTA}["
        for ((i=0; i<bar_len2; i++)); do
            printf "#"
        done
        printf "%*s]${NC} %8.2f μs" $((25-bar_len2)) "" "$time2"

        # Overhead percentage
        if (( $(echo "$overhead > 0" | bc -l) )); then
            printf " ${RED}+%6.2f%%${NC}\n" "$overhead"
        else
            printf " ${GREEN}%7.2f%%${NC}\n" "$overhead"
        fi
    fi
done < benchmark_comparison.csv

echo -e "\n${CYAN}■${NC} = With mitigations    ${MAGENTA}■${NC} = Without mitigations"

# Create a performance comparison chart for operations per second
print_header "Operations Per Second Comparison"
echo "Higher is better:"
echo ""

# Find the maximum ops/sec for scaling
max_ops=$(awk -F, 'NR>1 {if($6>max) max=$6; if($7>max) max=$7} END {print max}' benchmark_comparison.csv)
scale_factor=$(echo "scale=0; 25 / $max_ops" | bc)

# Print the chart
while IFS=, read -r test desc time1 time2 overhead ops1 ops2; do
    if [ "$test" != "test_type" ]; then
        # Calculate bar lengths
        bar_len1=$(echo "scale=0; $ops1 * $scale_factor / 1" | bc)
        bar_len2=$(echo "scale=0; $ops2 * $scale_factor / 1" | bc)

        # Print the bars side by side
        printf "%-15s " "$test"

        # Mitigated bar (cyan)
        printf "${CYAN}["
        for ((i=0; i<bar_len1; i++)); do
            printf "#"
        done
        printf "%*s]${NC} %10.2f/s" $((25-bar_len1)) "" "$ops1"

        # Unmitigated bar (magenta)
        printf " ${MAGENTA}["
        for ((i=0; i<bar_len2; i++)); do
            printf "#"
        done
        printf "%*s]${NC} %10.2f/s" $((25-bar_len2)) "" "$ops2"

        # Performance difference percentage
        perf_diff=$(echo "scale=2; 100 * ($ops2 - $ops1) / $ops1" | bc)
        if (( $(echo "$perf_diff > 0" | bc -l) )); then
            printf " ${GREEN}+%6.2f%%${NC}\n" "$perf_diff"
        else
            printf " ${RED}%7.2f%%${NC}\n" "$perf_diff"
        fi
    fi
done < benchmark_comparison.csv

echo -e "\n${CYAN}■${NC} = With mitigations    ${MAGENTA}■${NC} = Without mitigations"

echo -e "\n${GREEN}Benchmark comparison completed successfully${NC}"

# Clean up test files (optional)
read -p "Remove test files? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_header "Cleaning Up"
    rm -f "$file1" "$file2"
    echo "Test files removed"
fi
