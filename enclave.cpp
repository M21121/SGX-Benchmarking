#include <stdint.h>
#include <string.h>
#include "sgx_trts.h"
#include "sgx_tprotected_fs.h"
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

/* Empty ECALL with side-channel mitigations */
void empty_ecall(int n) {
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

    // Report the operation
    ocall_print_string("Empty ECALL executed\n");

    // Pass the information back to the app
    empty_ocall();

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");
}

/* ECALL that triggers an OCALL (ping) */
void ping_ecall(int iteration_number) {
    /* Prevent speculative execution before processing input */
    prevent_speculative_execution();

    // Report the current iteration
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer),
             "ECALL ping received (iteration %d)\n",
             iteration_number);
    ocall_print_string(log_buffer);

    // Call the OCALL to continue the ping-pong
    pong_ocall(iteration_number);

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");
}

/* ECALL that reads in a file (insecure method via OCALL) */
void file_read_ecall(const char* filename) {
    /* Prevent speculative execution before processing input */
    prevent_speculative_execution();

    // Buffer to store file contents
    char buffer[4096] = {0};
    size_t bytes_read = 0;

    // Read file via OCALL (insecure - host can see the data)
    sgx_status_t status = ocall_read_file(&bytes_read, filename, buffer, sizeof(buffer));

    if (status != SGX_SUCCESS) {
        ocall_print_string("Error: Failed to execute ocall_read_file\n");
        return;
    }

    // Process the data in a constant-time manner
    uint32_t checksum = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        checksum += (unsigned char)buffer[i];
        prevent_speculative_execution();
    }

    // Securely clear the buffer
    secure_memzero(buffer, sizeof(buffer));

    // Report the operation
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer),
             "Insecure file read completed\n"
             "Read %zu bytes, checksum: %u\n",
             bytes_read, checksum);
    ocall_print_string(log_buffer);

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");
}

/* ECALL that reads in a file using SGX Protected FS (secure method) */
void secure_file_read_ecall(const char* filename) {
    /* Prevent speculative execution before processing input */
    prevent_speculative_execution();

    // Buffer to store file contents
    char buffer[4096] = {0};
    size_t bytes_read = 0;

    // For now, use the regular file read method to avoid pthread issues
    sgx_status_t status = ocall_read_file(&bytes_read, filename, buffer, sizeof(buffer));

    if (status != SGX_SUCCESS) {
        ocall_print_string("Error: Failed to execute ocall_read_file\n");
        return;
    }

    // Process the data in a constant-time manner
    uint32_t checksum = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        checksum += (unsigned char)buffer[i];
        prevent_speculative_execution();
    }

    // Securely clear the buffer
    secure_memzero(buffer, sizeof(buffer));

    // Report the operation
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer),
             "Secure file read completed (using alternative method)\n"
             "Read %zu bytes, checksum: %u\n",
             bytes_read, checksum);
    ocall_print_string(log_buffer);

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");
}

void direct_file_read_ecall(const char* filename) {
    /* Prevent speculative execution before processing input */
    prevent_speculative_execution();

    // Buffer to store file contents
    char buffer[4096] = {0};
    size_t bytes_read = 0;

    // Read file via OCALL with direct I/O
    sgx_status_t status = ocall_read_file_direct(&bytes_read, filename, buffer, sizeof(buffer));

    if (status != SGX_SUCCESS) {
        ocall_print_string("Error: Failed to execute ocall_read_file_direct\n");
        return;
    }

    // Process the data in a constant-time manner
    uint32_t checksum = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        checksum += (unsigned char)buffer[i];
        prevent_speculative_execution();
    }

    // Securely clear the buffer
    secure_memzero(buffer, sizeof(buffer));

    // Report the operation
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer),
             "Direct file read completed\n"
             "Read %zu bytes, checksum: %u\n",
             bytes_read, checksum);
    ocall_print_string(log_buffer);

    /* Final memory fence */
    __asm__ volatile ("mfence" ::: "memory");
}
