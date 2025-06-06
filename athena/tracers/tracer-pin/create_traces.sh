#!/bin/bash

PIN_ROOT=$(pwd)/pintool

# setarch is used to disable ASLR
setarch `uname -m` -R ./pintool/pin -follow_execv -t $PWD/memtracer-pin-extension/obj-intel64/pinmemtracer.so -- $@
