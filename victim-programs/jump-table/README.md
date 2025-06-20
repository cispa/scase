# Jump-Table Example
This victim is a toy hex encoder, which is written to expose secret-dependant control- and data-flow leakage.

## Execute Recovery
Execute the file `./athena/hex_elf.py`.

## Compilation
Execute `make`.

## Trace Generation
Use Athena's angr tracer like this:
```
cd ./athena/tracers/tracer-angr/
python3 ./main.py something ../../../victim-programs/jump-table/main
```
Afterwards, copy the `cftrace.csv` and `dftrace.csv` from `tracers/tracer-angr` to the location specified in the variables `CFTRACE_FILE` and `DFTRACE_FILE` in `hex_elf.py`.
Also, adjust `TARGET_PATH` to point to the binary the trace stems from.