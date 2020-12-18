#!/bin/bash

PLUGIN_DIR=$HOME/sgx-forensic-2/volatility-plugin/
# NOTE: replace with real dump path
IMAGE_DUMP=$HOME/sgx-forensic/lime/src/hello-openenclave.bin

cd ~/volatility && ./vol.py --plugins="$PLUGIN_DIR" -f $IMAGE_DUMP$ --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 2304 --ebase  0x7f0345b00000