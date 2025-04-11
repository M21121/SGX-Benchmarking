### Important
I did not include results because the numbers are obviously incorrect (meaning I have bugs to fix).

### File Reading
This version implements two file read versions:
1) ocall_file_read - host just passes file directly to the enclave
2) sgx_fread - uses SGX protected FS, meaning the files stay encrypted from the host.

### Side-Channel Mitigations
This version has two makefiles. The second _removes_ the following side-channel mitigations:
- `-fstack-protector-strong`: Stack protection was removed, increasing vulnerability to buffer overflow attacks
- `-fno-omit-frame-pointer`: Frame pointer preservation was disabled, reducing debugging capabilities and stack trace accuracy
- `-mllvm -x86-speculative-load-hardening`: Speculative load hardening was removed, exposing data to Spectre-style attacks
- `-mindirect-branch=thunk`: Indirect branch speculation control was disabled, increasing vulnerability to branch target injection
- `-mfunction-return=thunk`: Return address prediction hardening was removed, exposing to return-based speculation attacks
- `-mindirect-branch-register`: Register-based indirect branch protection was disabled, weakening defense against branch prediction attacks
- `-Wl,-z,noexecstack`: Non-executable stack protection was removed, allowing code execution in stack memory
- `-Wl,-z,relro`: Read-only relocations were disabled, making GOT/PLT sections vulnerable to overwrites
- `-Wl,-z,now`: Immediate binding was removed, allowing lazy resolution exploits
- `-D_FORTIFY_SOURCE=2`: Source code fortification was disabled, removing compiler-inserted buffer overflow checks
- `lfence`: Explicit speculation barriers were removed, allowing speculative execution attacks
- `-O2` → `-O3`: Optimization level was increased, potentially removing security-relevant code patterns
- Memory barriers: Explicit memory fence instructions were removed, exposing to cache timing side-channel attacks
- Constant-time operations: Time-invariant code patterns were disabled, making cryptographic operations vulnerable to timing analysis


### Next steps:
- Fix bugs to get accurate timing.
- Make a version that gets rid of _all_ side-channel mitigations.
