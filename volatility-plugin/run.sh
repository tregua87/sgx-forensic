#!/bin/bash

PLUGIN_DIR=$HOME/sgx-forensic-2/volatility-plugin/
# NOTE: replace with real dump path
IMAGE_DUMP=$HOME/sgx-forensic/lime/src/hello-openenclave.bin

cd ~/volatility && ./vol.py --plugins="$PLUGIN_DIR" -f $IMAGE_DUMP$ --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 2304 --ebase  0x7f0345b00000


# other examples
./vol.py --plugins="/home/tregua/sgx-forensic/volatility-plugin/" -f /home/tregua/dumps/hello-openenclave.bin --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 7141 --ebase 0x7f2591000000 --framework openenclave 

./vol.py --plugins="/home/tregua/sgx-forensic/volatility-plugin/" -f /home/tregua/dumps/hello-asylo.bin --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 29381 --ebase 0x7fc8b4000000

./vol.py --plugins="/home/tregua/sgx-forensic/volatility-plugin/" -f /home/tregua/dumps/hello-graphene.bin --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 504 --ebase 0x40000000

./vol.py --plugins="/home/tregua/sgx-forensic/volatility-plugin/" -f /home/tregua/dumps/hello-sgxlkl.bin --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 8233 --ebase 0x7f8000000000

./vol.py --plugins="/home/tregua/sgx-forensic/volatility-plugin/" -f /home/tregua/dumps/hello-rustsdk.bin --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 10181 --ebase 0x7f18ab000000