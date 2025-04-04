#!/bin/bash

# benchmark.sh - Script to benchmark SGX application performance
# Measures execution time for ecalls, ocalls, pingpongs, and file operations

# Set the number of iterations
ITERATIONS=100000
FILE_ITERATIONS=1000  # Fewer iterations for file operations as they're slower
FILE_SIZE_1=1         # Size in KB for the first test file
FILE_SIZE_2=100       # Size in KB for the second test file

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

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
    local iter=${3:-$ITERATIONS}  # Use provided iterations or default
    local extra_args=${4:-""}     # Extra arguments for the command

    print_header "Benchmarking $desc ($iter iterations)"

    # Run the benchmark 3 times and take the average
    echo "Running 3 trials..."

    total_real=0
    total_user=0
    total_sys=0

    for i in {1..3}; do
        echo -e "\nTrial $i:"
        # Use time command with format that's easy to parse
        result=$( { /usr/bin/time -f "real %e\nuser %U\nsys %S" ./app --test $test_type --iterations $iter $extra_args; } 2>&1 )

        # Extract timing information
        real=$(echo "$result" | grep "real" | awk '{print $2}')
        user=$(echo "$result" | grep "user" | awk '{print $2}')
        sys=$(echo "$result" | grep "sys" | awk '{print $2}')

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
    avg_real=$(echo "scale=6; $total_real / 3" | bc)
    avg_user=$(echo "scale=6; $total_user / 3" | bc)
    avg_sys=$(echo "scale=6; $total_sys / 3" | bc)

    # Calculate operations per second
    ops_per_sec=$(echo "scale=2; $iter / $avg_real" | bc)

    # Display average results
    echo -e "\n${GREEN}Average Results:${NC}"
    echo "  Real time: ${avg_real}s"
    echo "  User time: ${avg_user}s"
    echo "  Sys time:  ${avg_sys}s"
    echo -e "${GREEN}Performance: $ops_per_sec operations/second${NC}"

    # Calculate time per operation in microseconds
    time_per_op=$(echo "scale=2; $avg_real * 1000000 / $iter" | bc)
    echo -e "${GREEN}Time per operation: $time_per_op microseconds${NC}"

    # Save results to CSV with a clean description (replace commas with spaces)
    clean_desc=$(echo "$desc" | tr ',' ' ')
    echo "$test_type,$clean_desc,$iter,$avg_real,$avg_user,$avg_sys,$ops_per_sec,$time_per_op" >> benchmark_results.csv
}

# Create test files of different sizes
create_test_file() {
    local size_kb=$1
    local filename="file_${size_kb}kb.txt"

    echo "Creating test file: $filename ($size_kb KB)"
    dd if=/dev/urandom of="$filename" bs=1K count="$size_kb" status=none
    echo "Created $filename: $(du -h $filename | cut -f1)"

    echo "$filename"  # Return the filename
}

# Check if the app exists
if [ ! -f "./app" ]; then
    echo -e "${RED}Error: 'app' executable not found. Please compile the application first.${NC}"
    exit 1
fi

# Create results CSV file with header
echo "test_type,description,iterations,avg_real_time,avg_user_time,avg_sys_time,ops_per_second,time_per_op_us" > benchmark_results.csv

# Print system information
print_header "System Information"
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo "CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d ':' -f2 | sed 's/^[ \t]*//')"
echo "CPU Cores: $(grep -c processor /proc/cpuinfo)"
echo "Memory: $(free -h | grep Mem | awk '{print $2}')"

# Create test files
print_header "Creating Test Files"
file1=$(create_test_file $FILE_SIZE_1)
file2=$(create_test_file $FILE_SIZE_2)

# Run basic benchmarks
run_benchmark "init" "Enclave Initialization Only" 100
run_benchmark "ecall" "Empty ECALL"
run_benchmark "ocall" "Empty OCALL"
run_benchmark "pingpong" "Ping-Pong (ECALL-OCALL round-trip)"

# Run file read benchmarks
print_header "File Read Benchmarks"
run_benchmark "fileread" "Single Read (${FILE_SIZE_1}KB File)" $FILE_ITERATIONS "--file $file1"
run_benchmark "fileread" "Single Read (${FILE_SIZE_2}KB File)" $FILE_ITERATIONS "--file $file2"

# Generate summary
print_header "Benchmark Summary"
echo "Results saved to benchmark_results.csv"

# Display CSV data in a readable format
echo -e "\nOperation               Description             Time/op (μs)    Ops/second"
echo "------------------------------------------------------------------------"
while IFS=, read -r test desc iterations real user sys ops_per_sec time_per_op; do
    if [ "$test" != "test_type" ]; then
        # Format the output with proper spacing
        printf "%-15s    %-25s    %8.2f          %10.2f\n" "$test" "$desc" "$time_per_op" "$ops_per_sec"
    fi
done < benchmark_results.csv

echo -e "\n${GREEN}Benchmark completed successfully${NC}"

# Clean up test files
print_header "Cleaning Up"
rm -f "$file1" "$file2"
echo "Test files removed"
