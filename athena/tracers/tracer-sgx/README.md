# Athena Tracer (Intel SGX)
This tracer uses SGX-Step to create a memory trace of an eCall from an Intel SGX enclave.

## Dependencies / Hardware Requirements
This tracer requires a CPU supporting Intel SGX and an installation of [SGX-Step](https://github.com/jovanbulck/sgx-step).

For instructions on how to install SGX-Step, please refer to [SGX-Step's documentation](https://github.com/jovanbulck/sgx-step?tab=readme-ov-file#building-and-running).
We assume that the for SGX-Step required environment variables are set correctly, e.g., `LD_LIBRARY_PATH` is pointing to the correct `sgxsdk`, and that the kernel module is loaded.

## Usage
Execute the following command:
```
./run-tracer.sh <target-enclave> <tracer-config>
```
Hereby, the tracer-config must be defined to match the already existing confics in `config.h`.
In summary, the config consists of the path to the enclave (`SGX_ENCLAVE_PATH`), the target function (`TARGET_FUNCTION`), and a function used to provide the target eCall with the corresponding arguments (`execute_ecall`)

### Example Tracer Config
```C
#ifdef CFG_SM_TRACE
#define SGX_ENCLAVE_PATH "../../../victim-programs/square-multiply-enclave/encl.so"
#define TARGET_FUNCTION "mod_exp_inner"

sgx_status_t execute_ecall(int* enclave_result) {
    uint64_t result = -1;
    // the enclave eCall
    sgx_status_t status = mod_exp(eid,
        &result);
    *enclave_result = result;
    return status;
}
#endif
```

### Example Execution
```
./run-tracer.sh ../../../victim-programs/square-multiply-enclave CFG_SM_TRACE
```
