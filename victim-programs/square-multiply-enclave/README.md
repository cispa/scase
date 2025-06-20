# Square-Multiply SGX Enclave
This victim is an Intel SGX enclave, which is written to expose secret-dependant control- and data-flow leakage.

## Dependencies / Hardware Requirements
The **recovery** itself requires around 62GB of allocatable RAM (at least in our tests, details may vary).
The **compilation** and **trace generation** requires a CPU supporting Intel SGX and an installation of [SGX-Step](https://github.com/jovanbulck/sgx-step).

For instructions on how to install SGX-Step, please refer to [SGX-Step's documentation](https://github.com/jovanbulck/sgx-step?tab=readme-ov-file#building-and-running).
We assume that the for SGX-Step required environment variables are set correctly, e.g., `LD_LIBRARY_PATH` is pointing to the correct `sgxsdk`, and that the kernel module is loaded.


## Execute Recovery
Execute the file `./athena/sm_enclave.py`.

## Compilation
Execute `make`.

## Trace Generation
Use Athena's SGX tracer like this:
```
cd ./athena/tracers/tracer-sgx/
./run-tracer.sh ../../../victim-programs/square-multiply-enclave CFG_SM_TRACE
```
Afterwards, copy the `cftrace.csv` and `dftrace.csv` from `tracers/tracer-sgx` to the location specified in the variables `CFTRACE_FILE` and `DFTRACE_FILE` in `sm_enclave.py`.
Also, adjust `TARGET_PATH` to point to the binary the trace stems from.