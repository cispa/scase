#! /bin/sh

if [ "$#" -lt 2 ]; then
    echo -e "USAGE:\n\t$0 <path-to-enclave-directory> <tracer-config-macro>\n"
    echo -e "Example:\n\t$0 \"../../examples/enclave\" CFG_EXAMPLE_CF_TRACE"
    exit 1
fi

ENCLAVE_PATH=$1
TRACER_CFG_MACRO=$2

# build the tracer
make clean

export ENCLAVE=${ENCLAVE_PATH}
make CFLAGS=\"-D${TRACER_CFG_MACRO}\"

# run the tracer
echo $ENCLAVE
sudo ./app
