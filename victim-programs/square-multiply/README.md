# Square-Multiply Example
This victim is a toy square+multiply implementation.

## Execute Recovery
Execute the file `./athena/square_elf_eval.py`.

## Compilation
Execute `make`.

## Trace Generation
Use Athena's angr tracer like this:
```
cd ./athena/tracers/tracer-angr/
python3 ./main.py mod_exp_inner ../../../victim-programs/square-multiply/main
```
Afterwards, copy the `cftrace.csv` and `dftrace.csv` from `tracers/tracer-angr` to the location specified in the variables `CFTRACE_FILE` and `DFTRACE_FILE` in `square_elf.py`.
Also, adjust `TARGET_PATH` to point to the binary the trace stems from.