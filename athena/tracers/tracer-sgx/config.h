#include <sgx_urts.h>

extern sgx_enclave_id_t eid;

//#define DEBUGMODE

#define MAX_LEN            15
#define DO_TIMER_STEP      0
#define DEBUG              1
#define DBG_ENCL           1
#define NUM_RUNS           100
#if DO_TIMER_STEP
    #define ANIMATION_DELAY    50000000
#else
    #define ANIMATION_DELAY    5000
#endif

// =============== CALLBACKS/VARIABLES TO IMPLEMENT/SET ========================

#ifdef CFG_SM_TRACE
#define SGX_ENCLAVE_PATH "../../../victim-programs/square-multiply-enclave/encl.so"
#define TARGET_FUNCTION "mod_exp_inner"

sgx_status_t execute_ecall(int* enclave_result) {
    uint64_t result = -1;
    // the enclave E-call
    sgx_status_t status = mod_exp(eid,
        &result);
    *enclave_result = result;
    return status;
}
#endif

#ifdef CFG_EXAMPLE_CF_TRACE
#define SGX_ENCLAVE_PATH "../../examples/enclave/encl.so"
#define TARGET_FUNCTION "mod_exp_inner"

sgx_status_t execute_ecall(int* enclave_result) {
    uint64_t result = -1;
    // the enclave E-call
    sgx_status_t status = mod_exp(eid,
        &result);
    *enclave_result = result;
    return status;
}
#endif

#ifdef CFG_EXAMPLE_DF_TRACE
#define SGX_ENCLAVE_PATH "../../examples/enclave-data-flow/encl.so"
#define TARGET_FUNCTION "key_access_inner"

sgx_status_t execute_ecall(int* enclave_result) {
    uint64_t result = -1;
    // the enclave E-call
    sgx_status_t status = key_access(eid,
        &result);
    *enclave_result = result;
    return status;
}
#endif

#ifdef CFG_RC4_TRACE
#define SGX_ENCLAVE_PATH "../../examples/rc4_enclave/encl.so"
#define TARGET_FUNCTION "KSA"

sgx_status_t execute_ecall(int* enclave_result) {
    uint64_t result = -1;
    // the enclave E-call
    sgx_status_t status = do_ksa(eid);
    return status;
}
#endif

#ifdef CFG_LUTMUL_TRACE
#define SGX_ENCLAVE_PATH "../../examples/lutmul_enclave/encl.so"
#define TARGET_FUNCTION "gf_mul"

sgx_status_t execute_ecall(int* enclave_result) {
    uint64_t result = -1;
    // the enclave E-call
    sgx_status_t status = do_gfops(eid,&result);
    return status;
}
#endif
