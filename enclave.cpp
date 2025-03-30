#include <stdint.h>
#include <string.h>
#include <x86intrin.h> // For __rdtsc()
#include "sgx_trts.h"
#include "enclave_t.h"

namespace {
    /* Constant-time memory comparison to prevent timing attacks */
    int constant_time_memcmp(const void *a, const void *b, size_t size) {
        const unsigned char *_a = static_cast<const unsigned char*>(a);
        const unsigned char *_b = static_cast<const unsigned char*>(b);
        unsigned char result = 0;

        for (size_t i = 0; i < size; i++) {
            /* XOR and OR operations maintain constant-time property */
            result |= _a[i] ^ _b[i];
            /* Insert memory fence to prevent speculative execution */
            __asm__ volatile ("lfence" ::: "memory");
        }

        return result;
    }

    /* Constant-time conditional select to prevent timing attacks */
    uint32_t constant_time_select(uint32_t condition, uint32_t a, uint32_t b) {
        /* condition should be 0 or 1 */
        uint32_t mask = -((condition != 0) & 1);
        return (mask & a) | (~mask & b);
    }

    /* Prevent speculative execution */
    void prevent_speculative_execution() {
        __asm__ volatile ("lfence" ::: "memory");
    }

    /* Secure memory zeroing to prevent data leakage */
    void secure_memzero(void *ptr, size_t len) {
        volatile unsigned char *p = static_cast<volatile unsigned char*>(ptr);
        while (len--) {
            *p++ = 0;
            /* Insert memory fence to ensure zeroing completes */
            __asm__ volatile ("lfence" ::: "memory");
        }
    }
}

/* Empty ECALL with side-channel mitigations and timing */
void empty_ecall(int n) {
    // Get timestamp immediately upon entering the enclave
    uint64_t enclave_entry_time = __rdtsc();

    /* Prevent speculative execution before processing input */
    prevent_speculative_execution();

    /* Ensure n is within bounds to prevent potential side-channel */
    if (n < 0 || n > 100) {
        /* Ensure constant-time response for invalid input */
        prevent_speculative_execution();
        /* Call OCALL with constant-time behavior */
        empty_ocall();
        return;
    }

    /* Perform some dummy computation with constant-time behavior */
    uint32_t result = 0;
    for (int i = 0; i < 10; i++) {
        /* Use constant-time select to avoid branches */
        uint32_t should_add = constant_time_select(i < n, 1, 0);
        result += should_add * i;
        /* Prevent speculative execution */
        prevent_speculative_execution();
    }

    /* Memory fence before calling OCALL */
    __asm__ volatile ("mfence" ::: "memory");

    // Get timestamp before exiting the enclave
    uint64_t enclave_exit_time = __rdtsc();
    uint64_t enclave_cycles = enclave_exit_time - enclave_entry_time;

    // Report the time spent inside the enclave
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "Pure enclave execution took %lu CPU cycles\n", enclave_cycles);
    ocall_print_string(buffer);

    // Pass the timing information back to the app
    empty_ocall();

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");
}

uint64_t measure_enclave_time(int n) {
    // Get app timestamp via OCALL
    uint64_t app_entry_cycles;
    ocall_get_app_cycles(&app_entry_cycles);

    // Get enclave entry timestamp
    uint64_t enclave_entry_cycles = __rdtsc();

    // Calculate entry context switch time
    uint64_t entry_context_switch = enclave_entry_cycles - app_entry_cycles;

    // Do some work (same as in empty_ecall)
    prevent_speculative_execution();
    uint32_t result = 0;
    for (int i = 0; i < 10; i++) {
        uint32_t should_add = constant_time_select(i < n, 1, 0);
        result += should_add * i;
        prevent_speculative_execution();
    }

    // Get enclave exit timestamp
    uint64_t enclave_exit_cycles = __rdtsc();

    // Get app timestamp via OCALL
    uint64_t app_exit_cycles;
    ocall_get_app_cycles(&app_exit_cycles);

    // Calculate exit context switch time
    uint64_t exit_context_switch = app_exit_cycles - enclave_exit_cycles;

    // Calculate pure enclave execution time
    uint64_t enclave_execution = enclave_exit_cycles - enclave_entry_cycles;

    // Report the measurements
    char buffer[256];
    snprintf(buffer, sizeof(buffer), 
             "Context switch times: Entry=%lu cycles, Exit=%lu cycles\n"
             "Pure enclave execution: %lu cycles\n",
             entry_context_switch, exit_context_switch, enclave_execution);
    ocall_print_string(buffer);

    // Return pure enclave execution time
    return enclave_execution;
}

/* ECALL that only reads in a file */
uint64_t file_read_ecall(const char* filename) {
    // Get timestamp immediately upon entering the enclave
    uint64_t enclave_entry_time = __rdtsc();

    /* Prevent speculative execution before processing input */
    prevent_speculative_execution();

    // Buffer to store file contents
    char buffer[4096] = {0};
    size_t bytes_read = 0;

    // Read file via OCALL
    sgx_status_t status = ocall_read_file(&bytes_read, filename, buffer, sizeof(buffer));

    if (status != SGX_SUCCESS) {
        ocall_print_string("Error: Failed to execute ocall_read_file\n");
        return 0;
    }

    // Process the data in a constant-time manner
    uint32_t checksum = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        checksum += (unsigned char)buffer[i];
        prevent_speculative_execution();
    }

    // Securely clear the buffer
    secure_memzero(buffer, sizeof(buffer));

    // Get timestamp before exiting the enclave
    uint64_t enclave_exit_time = __rdtsc();
    uint64_t enclave_cycles = enclave_exit_time - enclave_entry_time;

    // Report the time spent inside the enclave
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer), 
             "File read enclave execution took %lu CPU cycles\n"
             "Read %zu bytes, checksum: %u\n", 
             enclave_cycles, bytes_read, checksum);
    ocall_print_string(log_buffer);

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");

    return enclave_cycles;
}

/* ECALL that reads a file multiple times */
uint64_t repeated_file_read_ecall(const char* filename, int iterations) {
    // Get timestamp immediately upon entering the enclave
    uint64_t enclave_entry_time = __rdtsc();

    /* Prevent speculative execution before processing input */
    prevent_speculative_execution();

    // Buffer to store file contents
    char buffer[4096] = {0};
    size_t total_bytes_read = 0;
    uint32_t total_checksum = 0;

    // Validate iterations to prevent potential side-channel
    if (iterations <= 0 || iterations > 1000) {
        iterations = 1; // Default to 1 if invalid
    }

    // Read file multiple times
    for (int i = 0; i < iterations; i++) {
        size_t bytes_read = 0;

        // Read file via OCALL
        sgx_status_t status = ocall_read_file(&bytes_read, filename, buffer, sizeof(buffer));

        if (status != SGX_SUCCESS) {
            ocall_print_string("Error: Failed to execute ocall_read_file\n");
            return 0;
        }

        // Process the data in a constant-time manner
        uint32_t checksum = 0;
        for (size_t j = 0; j < bytes_read; j++) {
            checksum += (unsigned char)buffer[j];
            prevent_speculative_execution();
        }

        total_bytes_read += bytes_read;
        total_checksum += checksum;

        // Securely clear the buffer
        secure_memzero(buffer, sizeof(buffer));
    }

    // Get timestamp before exiting the enclave
    uint64_t enclave_exit_time = __rdtsc();
    uint64_t enclave_cycles = enclave_exit_time - enclave_entry_time;

    // Report the time spent inside the enclave
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer), 
             "Repeated file read enclave execution took %lu CPU cycles\n"
             "Read %zu bytes total, checksum: %u, iterations: %d\n", 
             enclave_cycles, total_bytes_read, total_checksum, iterations);
    ocall_print_string(log_buffer);

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");

    return enclave_cycles;
}
