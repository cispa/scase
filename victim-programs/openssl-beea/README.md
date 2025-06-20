# BEEA
This experiment attacks OpenSSL 1.1.0h's binary extended Euclidean algorithm (BEEA) implementation.

## Execute Recovery
Execute the file `./athena/beea_openssl.py`.

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
python3 ./main.py BN_gcd ../../../victim-programs/openssl-beea/main-minlibc
```
Afterwards, copy the `cftrace.csv` and `dftrace.csv` from `tracers/tracer-angr` to the location specified in the variables `CFTRACE_FILE` and `DFTRACE_FILE` in `beea_openssl.py`.
Also, adjust `TARGET_PATH` to point to the binary the trace stems from.