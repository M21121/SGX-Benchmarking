#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <iostream>
#include <stdexcept>
#include <chrono> // Add timing functionality
#include <vector> // For storing timing measurements
#include <fstream>
#include <x86intrin.h> // For __rdtsc()

#include "sgx_urts.h"
#include "enclave_u.h"


#include "sgx_urts.h"
#include "enclave_u.h"

struct TimingData {
    uint64_t app_start_cycles;
    uint64_t app_end_cycles;
    uint64_t enclave_cycles;
    double app_start_ms;
    double app_end_ms;
};

uint64_t ocall_get_app_cycles() {
    return __rdtsc();
}


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Error checking function with detailed error messages */
void check_error(sgx_status_t ret, const std::string& msg) {
    if (ret != SGX_SUCCESS) {
        std::cerr << "Error: " << msg << " (Error code: 0x" << std::hex << ret << ")" << std::endl;

        // Provide more detailed error information
        switch(ret) {
            case SGX_ERROR_INVALID_ENCLAVE:
                std::cerr << "Invalid enclave image" << std::endl;
                break;
            case SGX_ERROR_INVALID_PARAMETER:
                std::cerr << "Invalid parameter" << std::endl;
                break;
            case SGX_ERROR_OUT_OF_MEMORY:
                std::cerr << "Out of memory" << std::endl;
                break;
            case SGX_ERROR_ENCLAVE_FILE_ACCESS:
                std::cerr << "Can't open enclave file" << std::endl;
                break;
            case SGX_ERROR_INVALID_SIGNATURE:
                std::cerr << "Invalid enclave signature" << std::endl;
                break;
            // Add more error codes as needed
            default:
                std::cerr << "Unknown error" << std::endl;
        }

        throw std::runtime_error(msg);
    }
}

/* Initialize the enclave with better error reporting */
int initialize_enclave() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_launch_token_t token = {0};
    int updated = 0;

    std::cout << "Attempting to create enclave..." << std::endl;

    // Check if enclave file exists
    if (access("enclave.signed.so", F_OK) == -1) {
        std::cerr << "Error: enclave.signed.so does not exist" << std::endl;
        return -1;
    }

    /* Call sgx_create_enclave to initialize an enclave instance */
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, nullptr);

    if (ret != SGX_SUCCESS) {
        std::cerr << "Failed to create enclave (Error code: 0x" << std::hex << ret << ")" << std::endl;
        return -1;
    }

    std::cout << "Enclave created successfully. EID: " << global_eid << std::endl;
    return 0;
}

/* Set process security attributes */
void set_security_attributes() {
    std::cout << "Setting security attributes..." << std::endl;

    /* Flush CPU caches to mitigate cache-based side channels */
    // Commented out as this requires privileges and might cause issues
    // __asm__ volatile ("wbinvd" ::: "memory");

    /* Memory barrier to prevent instruction reordering */
    __asm__ volatile ("mfence" ::: "memory");

    std::cout << "Security attributes set" << std::endl;
}

void empty_ocall() {
    // Implementation of the untrusted function
    std::cout << "empty_ocall invoked" << std::endl;
}

// Add this function for enclave printing
void ocall_print_string(const char* str) {
    printf("%s", str);
}

// Function to identify physical cores (excluding hyperthreads)
std::vector<int> get_physical_cores() {
    std::vector<int> physical_cores;

    // Simple approach: on many systems, even-numbered cores are physical
    // This is a simplification and might not work on all systems
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    for (int i = 0; i < num_cores; i += 2) {
        physical_cores.push_back(i);
    }

    // More accurate approach (Linux-specific)
    for (int i = 0; i < num_cores; i++) {
        std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(i) + 
                          "/topology/thread_siblings_list";
        std::ifstream file(path);
        if (file.is_open()) {
            std::string line;
            if (std::getline(file, line)) {
                // If this core is the first in its siblings list, it's physical
                if (line[0] == std::to_string(i)[0]) {
                    physical_cores.push_back(i);
                }
            }
        }
    }

    return physical_cores;
}

void pin_to_physical_core() {
    auto physical_cores = get_physical_cores();

    if (physical_cores.empty()) {
        std::cerr << "Could not identify physical cores" << std::endl;
        return;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(physical_cores[0], &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == -1) {
        std::cerr << "Warning: Could not set CPU affinity" << std::endl;
    } else {
        std::cout << "Process pinned to physical CPU core " << physical_cores[0] << std::endl;
    }
}

void ocall_get_app_cycles(uint64_t* cycles) {
    if (cycles) {
        *cycles = __rdtsc();
    }
}

void measure_context_switch_time(int iterations) {
    std::cout << "\nMeasuring context switch time..." << std::endl;
    std::vector<uint64_t> context_switch_cycles;

    for (int i = 0; i < iterations; i++) {
        auto start_time = std::chrono::high_resolution_clock::now();

        uint64_t enclave_cycles = 0;
        sgx_status_t ret = measure_enclave_time(global_eid, &enclave_cycles, 42);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end_time - start_time;

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed to call measure_enclave_time (Error code: 0x" 
                      << std::hex << ret << ")" << std::endl;
            return;
        }

        // Calculate app-measured total time
        uint64_t app_cycles = duration.count() * 3.0e6; // Approximate conversion from ms to cycles

        // Context switch overhead is the difference
        uint64_t switch_cycles = app_cycles - enclave_cycles;

        context_switch_cycles.push_back(switch_cycles);
        std::cout << "Iteration " << (i+1) << ": " << std::endl;
        std::cout << "  Total time: " << duration.count() << " ms" << std::endl;
        std::cout << "  Enclave time: " << (enclave_cycles / 3.0e6) << " ms" << std::endl;
        std::cout << "  Context switch overhead: " << (switch_cycles / 3.0e6) << " ms" << std::endl;

        // Sleep briefly between iterations
        usleep(1000);
    }

    // Calculate and display context switch statistics
    uint64_t total_switch_cycles = 0;
    uint64_t min_switch_cycles = context_switch_cycles[0];
    uint64_t max_switch_cycles = context_switch_cycles[0];

    for (uint64_t cycles : context_switch_cycles) {
        total_switch_cycles += cycles;
        min_switch_cycles = std::min(min_switch_cycles, cycles);
        max_switch_cycles = std::max(max_switch_cycles, cycles);
    }

    double avg_switch_cycles = static_cast<double>(total_switch_cycles) / iterations;

    std::cout << "\nContext Switch Results:" << std::endl;
    std::cout << "  Average context switch cycles: " << avg_switch_cycles << std::endl;
    std::cout << "  Minimum context switch cycles: " << min_switch_cycles << std::endl;
    std::cout << "  Maximum context switch cycles: " << max_switch_cycles << std::endl;

    // Calculate approximate time in milliseconds (assuming ~3 GHz processor)
    const double CYCLES_PER_MS = 3.0e6; // 3 million cycles per millisecond at 3 GHz
    std::cout << "  Approximate context switch time: " << (avg_switch_cycles / CYCLES_PER_MS) << " ms" << std::endl;
}

size_t ocall_read_file(const char* filename, char* buf, size_t buf_len) {
    size_t bytes_read = 0;

    FILE* file = fopen(filename, "rb");
    if (file) {
        bytes_read = fread(buf, 1, buf_len - 1, file);
        buf[bytes_read] = '\0'; // Ensure null termination
        fclose(file);
    } else {
        std::cerr << "Error: Could not open file " << filename << std::endl;
    }

    return bytes_read;
}

void test_file_read_ecall(const char* filename, int iterations) {
    // First check if the file exists
    FILE* test_file = fopen(filename, "r");
    if (!test_file) {
        std::cerr << "Error: File '" << filename << "' does not exist. Please create it before running this test." << std::endl;
        return;
    }
    fclose(test_file);

    std::cout << "\nTesting file read ECALL with file: " << filename << std::endl;
    std::vector<uint64_t> file_read_cycles;
    std::vector<double> file_read_times;

    for (int i = 0; i < iterations; i++) {
        auto start_time = std::chrono::high_resolution_clock::now();

        uint64_t enclave_cycles = 0;
        sgx_status_t ret = file_read_ecall(global_eid, &enclave_cycles, filename);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end_time - start_time;

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed to call file_read_ecall (Error code: 0x" 
                      << std::hex << ret << ")" << std::endl;
            return;
        }

        file_read_cycles.push_back(enclave_cycles);
        file_read_times.push_back(duration.count());

        std::cout << "Iteration " << (i+1) << ":" << std::endl;
        std::cout << "  Total time: " << duration.count() << " ms" << std::endl;
        std::cout << "  Enclave cycles: " << enclave_cycles << std::endl;

        // Sleep briefly between iterations
        usleep(1000);
    }

    // Calculate statistics
    double total_time_sum = 0.0;
    uint64_t total_cycles_sum = 0;
    double min_time = file_read_times[0];
    double max_time = file_read_times[0];
    uint64_t min_cycles = file_read_cycles[0];
    uint64_t max_cycles = file_read_cycles[0];

    for (int i = 0; i < iterations; i++) {
        total_time_sum += file_read_times[i];
        total_cycles_sum += file_read_cycles[i];
        min_time = std::min(min_time, file_read_times[i]);
        max_time = std::max(max_time, file_read_times[i]);
        min_cycles = std::min(min_cycles, file_read_cycles[i]);
        max_cycles = std::max(max_cycles, file_read_cycles[i]);
    }

    double avg_time = total_time_sum / iterations;
    double avg_cycles = static_cast<double>(total_cycles_sum) / iterations;

    std::cout << "\nFile Read ECALL Results:" << std::endl;
    std::cout << "  Average execution time: " << avg_time << " ms" << std::endl;
    std::cout << "  Minimum execution time: " << min_time << " ms" << std::endl;
    std::cout << "  Maximum execution time: " << max_time << " ms" << std::endl;
    std::cout << "  Average enclave cycles: " << avg_cycles << std::endl;
    std::cout << "  Minimum enclave cycles: " << min_cycles << std::endl;
    std::cout << "  Maximum enclave cycles: " << max_cycles << std::endl;

    // Compare with empty ecall
    std::cout << "\nComparing with empty ECALL:" << std::endl;

    // Run empty ecall for comparison
    std::vector<double> empty_times;
    std::vector<uint64_t> empty_cycles;

    for (int i = 0; i < iterations; i++) {
        auto start_time = std::chrono::high_resolution_clock::now();

        sgx_status_t ret = empty_ecall(global_eid, 42);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end_time - start_time;

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed to call empty_ecall (Error code: 0x" 
                      << std::hex << ret << ")" << std::endl;
            return;
        }

        empty_times.push_back(duration.count());

        // Sleep briefly between iterations
        usleep(1000);
    }

    // Calculate empty ecall statistics
    double empty_time_sum = 0.0;
    for (double time : empty_times) {
        empty_time_sum += time;
    }
    double avg_empty_time = empty_time_sum / iterations;

    // Calculate overhead
    double overhead_time = avg_time - avg_empty_time;
    double overhead_percentage = (overhead_time / avg_empty_time) * 100.0;

    std::cout << "  Average empty ECALL time: " << avg_empty_time << " ms" << std::endl;
    std::cout << "  File read overhead: " << overhead_time << " ms (" 
              << overhead_percentage << "% increase)" << std::endl;
}

void test_repeated_file_read_ecall(const char* filename, int iterations_per_call, int num_calls) {
    // First check if the file exists
    FILE* test_file = fopen(filename, "r");
    if (!test_file) {
        std::cerr << "Error: File '" << filename << "' does not exist. Please create it before running this test." << std::endl;
        return;
    }
    fclose(test_file);

    std::cout << "\nTesting repeated file read ECALL with file: " << filename << std::endl;
    std::cout << "Performing " << iterations_per_call << " reads per ECALL, " << num_calls << " calls" << std::endl;

    std::vector<uint64_t> file_read_cycles;
    std::vector<double> file_read_times;

    for (int i = 0; i < num_calls; i++) {
        auto start_time = std::chrono::high_resolution_clock::now();

        uint64_t enclave_cycles = 0;
        sgx_status_t ret = repeated_file_read_ecall(global_eid, &enclave_cycles, filename, iterations_per_call);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration = end_time - start_time;

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed to call repeated_file_read_ecall (Error code: 0x" 
                      << std::hex << ret << ")" << std::endl;
            return;
        }

        file_read_cycles.push_back(enclave_cycles);
        file_read_times.push_back(duration.count());

        std::cout << "Call " << (i+1) << ":" << std::endl;
        std::cout << "  Total time: " << duration.count() << " ms" << std::endl;
        std::cout << "  Enclave cycles: " << enclave_cycles << std::endl;
        std::cout << "  Average time per read: " << (duration.count() / iterations_per_call) << " ms" << std::endl;

        // Sleep briefly between iterations
        usleep(1000);
    }

    // Calculate statistics
    double total_time_sum = 0.0;
    uint64_t total_cycles_sum = 0;
    double min_time = file_read_times[0];
    double max_time = file_read_times[0];
    uint64_t min_cycles = file_read_cycles[0];
    uint64_t max_cycles = file_read_cycles[0];

    for (int i = 0; i < num_calls; i++) {
        total_time_sum += file_read_times[i];
        total_cycles_sum += file_read_cycles[i];
        min_time = std::min(min_time, file_read_times[i]);
        max_time = std::max(max_time, file_read_times[i]);
        min_cycles = std::min(min_cycles, file_read_cycles[i]);
        max_cycles = std::max(max_cycles, file_read_cycles[i]);
    }

    double avg_time = total_time_sum / num_calls;
    double avg_cycles = static_cast<double>(total_cycles_sum) / num_calls;
    double avg_time_per_read = avg_time / iterations_per_call;
    double avg_cycles_per_read = avg_cycles / iterations_per_call;

    std::cout << "\nRepeated File Read ECALL Results:" << std::endl;
    std::cout << "  Average execution time per call: " << avg_time << " ms" << std::endl;
    std::cout << "  Minimum execution time per call: " << min_time << " ms" << std::endl;
    std::cout << "  Maximum execution time per call: " << max_time << " ms" << std::endl;
    std::cout << "  Average enclave cycles per call: " << avg_cycles << std::endl;
    std::cout << "  Average time per individual read: " << avg_time_per_read << " ms" << std::endl;
    std::cout << "  Average cycles per individual read: " << avg_cycles_per_read << std::endl;
}



int main(int argc, char* argv[]) {
    try {
        std::cout << "Starting SGX application..." << std::endl;

        pin_to_physical_core();

        /* Apply side-channel mitigations */
        set_security_attributes();

        /* Initialize the enclave */
        if (initialize_enclave() < 0) {
            std::cerr << "Failed to initialize enclave" << std::endl;
            return -1;
        }

        /* Perform empty ECALL with timing */
        const int NUM_ITERATIONS = 10; // Number of iterations to measure
        std::vector<double> total_times;
        std::vector<double> context_switch_times;
        std::vector<double> enclave_times;

        std::cout << "Running empty_ecall for " << NUM_ITERATIONS << " iterations..." << std::endl;

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            // Measure total time (including context switch)
            auto start_time = std::chrono::high_resolution_clock::now();
            uint64_t start_cycles = __rdtsc();

            sgx_status_t ret = empty_ecall(global_eid, 42);

            uint64_t end_cycles = __rdtsc();
            auto end_time = std::chrono::high_resolution_clock::now();

            if (ret != SGX_SUCCESS) {
                std::cerr << "Failed to call empty_ecall (Error code: 0x" << std::hex << ret << ")" << std::endl;
                sgx_destroy_enclave(global_eid);
                return -1;
            }

            // Calculate timing
            std::chrono::duration<double, std::milli> total_duration = end_time - start_time;
            uint64_t total_cycles = end_cycles - start_cycles;

            // Store results
            total_times.push_back(total_duration.count());

            std::cout << "Iteration " << (i+1) << ":" << std::endl;
            std::cout << "  Total time (with context switch): " << total_duration.count() << " ms" << std::endl;
            std::cout << "  Total cycles: " << total_cycles << std::endl;

            // Sleep briefly between iterations
            usleep(1000);
        }

        // Calculate and display statistics for empty_ecall
        double total_time_sum = 0.0;
        double min_total_time = total_times[0];
        double max_total_time = total_times[0];

        for (double time : total_times) {
            total_time_sum += time;
            min_total_time = std::min(min_total_time, time);
            max_total_time = std::max(max_total_time, time);
        }

        double avg_total_time = total_time_sum / NUM_ITERATIONS;

        std::cout << "\nEmpty ECALL Timing Results:" << std::endl;
        std::cout << "  Average total execution time: " << avg_total_time << " ms" << std::endl;
        std::cout << "  Minimum total execution time: " << min_total_time << " ms" << std::endl;
        std::cout << "  Maximum total execution time: " << max_total_time << " ms" << std::endl;

        // Now measure context switch time specifically
        measure_context_switch_time(NUM_ITERATIONS);

        // Measure multiple back-to-back ECALLs to see overhead pattern
        std::cout << "\nMeasuring multiple back-to-back ECALLs..." << std::endl;
        const int MULTI_CALLS = 100;

        auto multi_start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < MULTI_CALLS; i++) {
            sgx_status_t ret = empty_ecall(global_eid, i % 50); // Vary the parameter slightly

            if (ret != SGX_SUCCESS) {
                std::cerr << "Failed in multi-call test (Error code: 0x" << std::hex << ret << ")" << std::endl;
                sgx_destroy_enclave(global_eid);
                return -1;
            }
        }

        auto multi_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> multi_duration = multi_end - multi_start;

        std::cout << "  " << MULTI_CALLS << " back-to-back ECALLs took: " << multi_duration.count() << " ms" << std::endl;
        std::cout << "  Average time per ECALL: " << (multi_duration.count() / MULTI_CALLS) << " ms" << std::endl;

        const char* test_filename = "test_file.txt";

        // Test the file read ecall
        test_file_read_ecall(test_filename, NUM_ITERATIONS);
        // Test the repeated file read ecall
        test_repeated_file_read_ecall(test_filename, 100, NUM_ITERATIONS);


        /* Destroy the enclave */
        std::cout << "\nDestroying enclave..." << std::endl;
        sgx_status_t ret = sgx_destroy_enclave(global_eid);

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed to destroy enclave (Error code: 0x" << std::hex << ret << ")" << std::endl;
            return -1;
        }

        std::cout << "Program completed successfully" << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return -1;
    }
}
