# Athena Tracer (angr)
This tracer uses angr itself to create memory traces, allowing for more flexibility.

## Usage
Execute the following command:
```
python3 ./main.py <target-function> <victim-binary>
```
Hereby, target function is the function from which the memory trace should start.

### Example
`python3 ./main.py mod_exp_inner ../../examples/sm`
