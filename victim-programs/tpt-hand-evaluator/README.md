# TwoPlusTwo Hand Evaluator
This victim is a poker hand evaluator.

## Execute Recovery
Execute the file `./athena/poker_elf.py`.

## Compilation
Execute `make`.

## Trace Generation
Use Athena's angr tracer like this:
```
cd ./athena/tracers/tracer-angr/
python3 ./main.py LookupHand ../../../victim-programs/tpt-hand-evaluator/victim
```
Afterwards, copy the `cftrace.csv` and `dftrace.csv` from `tracers/tracer-angr` to the location specified in the variables `CFTRACE_FILE` and `DFTRACE_FILE` in `poker_elf.py`.
Also, adjust `TARGET_PATH` to point to the binary the trace stems from.