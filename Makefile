# Makefile with side-channel mitigations

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_FLAGS += -O0 -g
else
	# Use -O2 instead of -O3 to avoid aggressive optimizations that might introduce timing side channels
	SGX_COMMON_FLAGS += -O2
endif

# Add side-channel mitigation flags
SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
					-Waddress -Wsequence-point -Wformat-security \
					-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
					-Wcast-align -Wcast-qual -Wconversion -Wredundant-decls \
					-fno-strict-aliasing -fstack-protector-strong \
					-fPIE -fno-omit-frame-pointer -mllvm -x86-speculative-load-hardening

# Add Spectre/Meltdown mitigations
SGX_COMMON_FLAGS += -mindirect-branch=thunk -mfunction-return=thunk \
					-mindirect-branch-register -mno-indirect-branch-register

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## App Settings ########

App_Cpp_Files := app.cpp
App_Include_Paths := -I$(SGX_SDK)/include

App_Cpp_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_Cpp_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_Cpp_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_Cpp_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

# Add side-channel mitigation flags for app
App_Cpp_Flags += -fstack-protector-all -D_FORTIFY_SOURCE=2

App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -lpthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## Enclave Settings ########

Enclave_Cpp_Files := enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

# Add side-channel mitigation flags for enclave
Enclave_Cpp_Flags := $(Enclave_Include_Paths) -nostdinc++ -fvisibility=hidden -fpie -fstack-protector-strong
Enclave_Cpp_Flags += -fno-builtin-printf

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,-z,relro -Wl,-z,now

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

.PHONY: all clean

all: $(App_Name) $(Signed_Enclave_Name)

######## App Objects ########

enclave_u.c: $(SGX_EDGER8R) enclave.edl
	@$(SGX_EDGER8R) --untrusted enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave_u.o: enclave_u.c
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

app.o: app.cpp enclave_u.c
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): app.o enclave_u.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

enclave_t.c: $(SGX_EDGER8R) enclave.edl
	@$(SGX_EDGER8R) --trusted enclave.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave_t.o: enclave_t.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

enclave.o: enclave.cpp enclave_t.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): enclave.o enclave_t.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) *.o enclave_t.* enclave_u.*