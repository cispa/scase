#!/bin/bash
HERE1=$(pwd)
if [ ! -d pintool ];
then
    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz -O ./pin.tar.gz
    tar xzvf pin.tar.gz
    rm pin.tar.gz
    mv pin* pintool
fi

export PIN_ROOT=$(pwd)/pintool
cd ./memtracer-pin-extension && make && cd ../
cp ./memtracer-pin-extension/obj-intel64/pinmemtracer.so $PIN_ROOT
