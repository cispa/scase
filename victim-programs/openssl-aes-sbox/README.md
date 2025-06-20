# AES S-Box
This experiment attacks OpenSSL 1.0.2p's AES S-Box implementation.

## Execute Recovery
Execute the file `./athena/aes_openssl.py` or `./athena/aes_openssl_eval.py`.
The latter executes the victim with varying leakage granularities.

## Compilation
First, you must compile OpenSSL.
Second, you compile the actual victim linking against the library

### OpenSSL Compililation
Execute the following commands:

```
cd ./openssl
./config
make
```
Eventually, ensure that the files `./openssl/libcrypto.a` and `./openssl/libssl.a` exist.

### Victim Compilation
Execute `make`.

## Trace Generation
Use Athena's angr tracer like this:
```
cd ./athena/tracers/tracer-angr/
python3 ./main.py AES_encrypt ../../../victim-programs/openssl-aes-sbox/victim
```
Afterwards, copy the `cftrace.csv` and `dftrace.csv` from `tracers/tracer-angr` to the location specified in the variables `CFTRACE_FILE` and `DFTRACE_FILE` in `aes_openssl.py`.
Also, adjust `TARGET_PATH` to point to the binary the trace stems from.