Right now I'm converting from cycles to ms. This is inaccurate, but still gives good insight into relative speed between operations.

### Side-Channel Mitigations Implemented

- Use of ```lfence``` instructions to prevent speculative execution
- Speculative load hardening via compiler flags (```-mllvm -x86-speculative-load-hardening```)
- Indirect branch protection (```-mindirect-branch=thunk```, ```-mfunction-return=thunk```)
- Constant-time memory comparison function
- Constant-time conditional select to avoid branches
- Use of memory fences (```mfence```) to prevent instruction reordering
- Pinning process to physical core to reduce timing variability and prevent hyperthreading issues
- Secure memory zeroing to prevent data leakage
- Stack protection (```-fstack-protector-strong```, ```-fstack-protector-all```)
- Non-executable stack (```-Wl,-z,noexecstack```)
- Conservative optimization level (O2 instead of O3)
- Various warning flags to catch potential vulnerabilities
- Position Independent Execution (```-fPIE```)
- Fortified source (```-D_FORTIFY_SOURCE=2```)
- RELRO protection (```-Wl,-z,relro -Wl,-z,now```)
- Frame pointer preservation (```-fno-omit-frame-pointer```)
