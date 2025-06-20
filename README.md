# SCASE
This repository contains the implementation of the Athena framework discussed in the *upcoming* research paper ["SCASE: Automated Secret Recovery via Side-Channel-Assisted Symbolic Execution" (USENIX 2025) (Link follows soon)](TODO). 

The framework automates the recovery of secrets from a given side-channel memory trace.

## Supported Platforms
The main component of Athena, i.e., its recovery engine, requires no specific platform.
However, the SGX tracing component is build on top of [SGX-Step](https://github.com/jovanbulck/sgx-step) and targets Intel SGX enclaves, thus requiring a CPU compatible with SGX and system compatible with SGX-Step, e.g., Ubuntu 22.04.
The code was developed and tested on Ubuntu 22.04 and Arch Linux.

## Dependencies
Most dependencies can be installed by simply running `pip3 install -r ./athena/requirements.txt`.
Furthermore, one needs to install the following (Ubuntu) packages:
```
apt install build-essential libelf-dev 
```
For the SGX tracing component, one needs to install [SGX-Step](https://github.com/jovanbulck/sgx-step) according to the installation instructions in its repo.

## Contact
If there are questions regarding this tool, please send an email to `daniel.weber (AT) cispa.de`.

## Research Paper
The paper will be available [very soon](TODO).
You can cite our work with the following BibTeX entry:
```
@inproceedings{Weber2025SCASE,
 author={Weber, Daniel and Gerlach, Lukas and Trampert, Leon and Lue, Youheng and Van Bulck, Jo and Schwarz, Michael},
 booktitle = {USENIX},
 title={SCASE: Automated Secret Recovery via Side-Channel-Assisted Symbolic Execution},
 year = {2025}
}
```

## Disclaimer
We are providing this code as-is. 
You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. 
This code may cause unexpected and undesirable behavior to occur on your machine. 
