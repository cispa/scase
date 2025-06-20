# Athena Framework
This folder contains the Athena framework itself.

## Dependencies
Most dependencies can be installed by simply running:
```
# create a venv for the project
python3 -m venv ./venv
source ./venv/bin/activate

# install the dependencies
pip3 install -r ./requirements.txt
```
Furthermore, one needs to install the following (Ubuntu) packages:
```
apt install build-essentials libelf-dev 
```
For the SGX tracing component, one needs to install [SGX-Step](https://github.com/jovanbulck/sgx-step) according to the installation instructions in its repo.

## Usage
Athena recovers annotated secrets by recovering them from memory traces stemming from side-channel attacks.
Thus, a normal workflow looks like the following:
1) Mount a side-channel attack or likewise to create a memory trace (explained below).
2) Write a *Athena wrapper*, i.e., a script using the Athena framework to recover the secret.

### Trace Generation
The memory traces processed by Athena are simple CSV files consisting of entries the following format:
```
virt_addr;rip
<addr>;<addr>
```
Hereby, `virt_addr` refers to the address Athena uses for its internal guidance and `rip` refers to an optional debug address, which can just be  `0x0` for Athena to ignore it.
If provided, the debug address will be used in certain debug prints.
Athena requires memory traces to be split into control and data flow memory traces, our scripts and tracers refer to them as `cftrace` and `dftrace`, respectively.

To create such traces, we already provide different *tracers* in `./tracers`, whose usage is explained in their own README files, e.g., `./tracers/tracer-angr/README.md`.
While these tracers were used during our paper, users can create their own side-channel attacks resulting in the previously introduced CSV format.

### Secret Recovery / Writing Athena Wrappers
*Athena wrapper* is the term we use to refer to Python scripts that use our framework to recover secrets.
The current folder has varies examples for such wrappers that we used during our experiments, e.g., a simple example can be found in `./hex_elf.py`.

First, you need to import athena:
```python
from engine import athena
```
Next, you need to create an instance of the framework provided with the paths to the victim binary (`TARGET_PATH`) and the memory traces (`CFTRACE_FILE` and `DFTRACE_FILE`):
```python
athena_framework = athena.AthenaFramework(
    TARGET_PATH, 
    TARGET_ECALL, 
    TARGET_FUNC,
    enable_control_flow_tracing=True,
    control_flow_tracefile=CFTRACE_FILE,
    enable_data_flow_tracing=True,
    data_flow_tracefile=DFTRACE_FILE,
    base_addr=BINARY_BASE_ADDR,
    target_is_enclave=False,
    verbose=True)
```
Two mandatory arguments are `TARGET_ECALL` and `TARGET_FUNC`.
These denote the ELF symbol at which the symbolic execution starts (`TARGET_ECALL`) and the ELF symbol at which the secret is symbolized and the memory trace starts.
Note that `TARGET_ECALL` does not need to point to an actual eCall if the target is not an Intel SGX enclave.
The arguments `enable_control_flow_tracing` and `enable_data_flow_tracing` can be used to restrict Athena to only one type of memory traces.
`base_addr` is the binary's `.text` base address.
For our tracers, it can be either extracted from the tracer itself, e.g., for the SGX tracer, or can be left as 0x0, e.g., for the angr tracer.
The argument `target_is_enclave` tells Athena whether it should treat the argument in `TARGET_PATH` as an Intel SGX enclave or a standalone ELF binary.

Next, you need to tell Athena which secret you want to extract.
For this, Athena gives you its initial state, which is an angr state at the position `TARGET_FUNC`.
You job is to symbolize the secret you want to extract.
For example, if your secret is a 128 bit array pointed to by `RDI`, you can write:
```python
initial_state = athena_framework.get_initial_state()

# create a symbolic bitvector
secret = initial_state.solver.BVS("secret", 128)

# assign that symbolic bitvector to the address stored in RDI
rdi_ptr = initial_state.regs.rdi.concrete_value
initial_state.memory.store(rdi_ptr, secret)

# give Athena the annotated state
athena_framework.set_initial_state(initial_state)
```

Afterwards, you can start the actual emulation:
```python
athena_framework.run()
```
Eventually, you can ask Athena to concretize your secret.
```python
solution = athena_framework.solve(secret)
```

### Example
Putting it all together, a minimal example looks like:
```python
from engine import athena

athena_framework = athena.AthenaFramework(
    TARGET_PATH, 
    TARGET_ECALL, 
    TARGET_FUNC,
    enable_control_flow_tracing=True,
    control_flow_tracefile=CFTRACE_FILE,
    enable_data_flow_tracing=True,
    data_flow_tracefile=DFTRACE_FILE,
    base_addr=BINARY_BASE_ADDR,
    target_is_enclave=False,
    verbose=True)

initial_state = athena_framework.get_initial_state()

# create a symbolic bitvector
secret = initial_state.solver.BVS("secret", 128)

# assign that symbolic bitvector to the address stored in RDI
rdi_ptr = initial_state.regs.rdi.concrete_value
initial_state.memory.store(rdi_ptr, secret)

# give Athena the annotated state
athena_framework.set_initial_state(initial_state)

# start the emulation
athena_framework.run()

# read out the recovered secret
solution = athena_framework.solve(secret)
```

## File Overview
- `engine`: The Athena core implementation (Section 4).
- `tracers`: The different scripts to generate memory traces (Section 4.2).
- `dependencies`: dependencies required by `requirements.txt`.
- `requirements.txt`: The required Python packages.
- `aes_openssl.py`: The script to attack `victim-program/openssl-aes-sbox` (Section 5.3).
- `aes_openssl_eval.py`: The script to evaluate different attacks against `victim-program/openssl-aes-sbox` (Section 5.3).
- `beea_openssl.py`: The script to attack `victim-program/openssl-beea` (Section 5.4).
- `hex_elf.py`: The script to attack `victim-program/jump-table` (Section 5.1.1).
- `hex_elf_eval.py`: The script to evaluate different attacks against `victim-program/jump-table` (Section 5.1.1).
- `poker_elf.py`: The script to attack `victim-program/tpt-hand-evaluator` (Section 5.6)
- `rc4_elf.py`: The script to attack `victim-program/rc4-ksa` (Section 5.5).
- `sm_enclave.py`: The script to attack `victim-program/square-multiply-enclave` (Section 5.2).
- `square_elf_eval.py`: The script to evaluate different attacks against `victim-program/square-multiply` (Section 5.1.2).

## Disclaimer
We are providing this code as-is. 
You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. 
This code may cause unexpected and undesirable behavior to occur on your machine. 