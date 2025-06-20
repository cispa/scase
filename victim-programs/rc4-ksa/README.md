# RC4 Key Scheduling Algorithm
This victim is a toy RC4 key-scheduling algorithm implementation.

## Execute Recovery
Execute the file `./athena/rc4_elf.py`.

## Compilation
Execute `make`.

## Trace Generation
Use Athena's angr tracer like this:
```
cd ./athena/tracers/tracer-angr/
python3 ./main.py KSA ../../../victim-programs/rc4-ksa/main
```
Afterwards, copy the `cftrace.csv` and `dftrace.csv` from `tracers/tracer-angr` to the location specified in the variables `CFTRACE_FILE` and `DFTRACE_FILE` in `rc4_elf.py`.
Also, adjust `TARGET_PATH` to point to the binary the trace stems from.