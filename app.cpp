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
#include <fstream>
#include <vector>
#include <getopt.h>

#include "sgx_urts.h"
#include "enclave_u.h"

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

void pong_ocall(int iteration_number) {
    std::cout << "OCALL pong received (iteration " << iteration_number << ")" << std::endl;
}

void test_init_only() {
    std::cout << "\nTesting enclave initialization only (control test)" << std::endl;
    std::cout << "Enclave was initialized successfully and will now be destroyed" << std::endl;
    // No operations performed - this is just a control test
}

void test_ping_pong(int iterations) {
    std::cout << "\nTesting ping-pong between ECALL and OCALL for " << iterations << " iterations..." << std::endl;

    for (int i = 1; i <= iterations; i++) {
        // Start the ping-pong with an ECALL
        sgx_status_t ret = ping_ecall(global_eid, i);

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed in ping_ecall (Error code: 0x" << std::hex << ret << ")" << std::endl;
            return;
        }
    }

    std::cout << "Completed ping-pong test with " << iterations << " iterations" << std::endl;
}

void test_empty_ecall(int iterations) {
    std::cout << "\nTesting empty_ecall for " << iterations << " iterations..." << std::endl;

    for (int i = 0; i < iterations; i++) {
        sgx_status_t ret = empty_ecall(global_eid, i % 50); // Vary the parameter slightly

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed in empty_ecall test (Error code: 0x" << std::hex << ret << ")" << std::endl;
            return;
        }
    }

    std::cout << "Completed " << iterations << " empty_ecall operations" << std::endl;
}

void test_empty_ocall(int iterations) {
    std::cout << "\nTesting empty_ocall for " << iterations << " iterations..." << std::endl;

    for (int i = 0; i < iterations; i++) {
        empty_ocall();
    }

    std::cout << "Completed " << iterations << " empty_ocall operations" << std::endl;
}

void test_file_read_ecall(const char* filename, int iterations) {
    // First check if the file exists
    FILE* test_file = fopen(filename, "r");
    if (!test_file) {
        std::cerr << "Error: File '" << filename << "' does not exist. Please create it before running this test." << std::endl;
        return;
    }
    fclose(test_file);

    std::cout << "\nTesting file_read_ecall with file: " << filename << std::endl;
    std::cout << "Performing " << iterations << " iterations" << std::endl;

    for (int i = 0; i < iterations; i++) {
        sgx_status_t ret = file_read_ecall(global_eid, filename);

        if (ret != SGX_SUCCESS) {
            std::cerr << "Failed to call file_read_ecall (Error code: 0x"
                      << std::hex << ret << ")" << std::endl;
            return;
        }
    }

    std::cout << "Completed " << iterations << " file_read_ecall operations" << std::endl;
}


void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                 Show this help message" << std::endl;
    std::cout << "  -t, --test TYPE            Test type (init, ecall, ocall, fileread, pingpong)" << std::endl;
    std::cout << "  -i, --iterations N         Number of iterations to run (default: 1)" << std::endl;
    std::cout << "  -f, --file FILENAME        File to use for file operations (default: test_file.txt)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " --test init                # Just initialize enclave and exit (control test)" << std::endl;
    std::cout << "  " << program_name << " --test ecall --iterations 1000" << std::endl;
    std::cout << "  " << program_name << " --test fileread --file data.txt --iterations 10" << std::endl;
    std::cout << "  " << program_name << " --test pingpong --iterations 10" << std::endl;
}


int main(int argc, char* argv[]) {
    try {
        // Default values
        std::string test_type = "";
        int iterations = 1;
        std::string filename = "test_file.txt";
        int reads_per_call = 100;

        // Define command line options
        static struct option long_options[] = {
            {"help",           no_argument,       0, 'h'},
            {"test",           required_argument, 0, 't'},
            {"iterations",     required_argument, 0, 'i'},
            {"file",           required_argument, 0, 'f'},
            {0, 0, 0, 0}
        };

        // Parse command line arguments
        int opt;
        int option_index = 0;
        while ((opt = getopt_long(argc, argv, "ht:i:f:", long_options, &option_index)) != -1) {
            switch (opt) {
                case 'h':
                    print_usage(argv[0]);
                    return 0;
                case 't':
                    test_type = optarg;
                    break;
                case 'i':
                    iterations = std::stoi(optarg);
                    break;
                case 'f':
                    filename = optarg;
                    break;
                default:
                    print_usage(argv[0]);
                    return 1;
            }
        }

        // Validate arguments
        if (test_type.empty()) {
            std::cerr << "Error: Test type must be specified" << std::endl;
            print_usage(argv[0]);
            return 1;
        }

        if (iterations <= 0) {
            std::cerr << "Error: Iterations must be a positive number" << std::endl;
            return 1;
        }

        if (reads_per_call <= 0) {
            std::cerr << "Error: Reads per call must be a positive number" << std::endl;
            return 1;
        }

        std::cout << "Starting SGX application..." << std::endl;

        pin_to_physical_core();

        /* Apply side-channel mitigations */
        set_security_attributes();

        /* Initialize the enclave */
        if (initialize_enclave() < 0) {
            std::cerr << "Failed to initialize enclave" << std::endl;
            return -1;
        }

        // Run the specified test
        if (test_type == "ecall") {
            test_empty_ecall(iterations);
        } else if (test_type == "ocall") {
            test_empty_ocall(iterations);
        } else if (test_type == "fileread") {
            test_file_read_ecall(filename.c_str(), iterations);
        } else if (test_type == "pingpong") {
            test_ping_pong(iterations);
        } else if (test_type == "init") {
            test_init_only();
        } else {
            std::cerr << "Error: Unknown test type '" << test_type << "'" << std::endl;
            print_usage(argv[0]);
            sgx_destroy_enclave(global_eid);
            return 1;
        }


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

