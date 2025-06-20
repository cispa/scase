# Athena Framework
This folder contains the Athena framework itself.

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
TODO

## Disclaimer
We are providing this code as-is. 
You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. 
This code may cause unexpected and undesirable behavior to occur on your machine. 