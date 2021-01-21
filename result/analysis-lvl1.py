#!/usr/bin/env python3

import sys, os, re
import subprocess
from pathlib import Path

def run_analysis(samples, profile):
    global RESULT_DIR
    global VOLATILITY_PLUGIN_DIR
    global VOLATILITY_DIR
    global DUMP_DIR

    for tag, dumps in samples.items():
        print(f"tag: {tag}")
        for d in dumps:
            outputfile_json = RESULT_DIR + d.replace(".bin", ".json")
            # from IPython import embed; embed(); exit()
            cmd_str = f"time ./vol.py --plugins={VOLATILITY_PLUGIN_DIR} -f {DUMP_DIR}{d} --profile={profile} linux_sgx --output=json --output-file={outputfile_json}"
            cmd = cmd_str.split(' ')
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=VOLATILITY_DIR)
            # my_output = result.stdout.decode('utf-8')
            my_output = result.stderr.decode('utf-8')
            # from IPython import embed; embed(); exit()
            user_time = re.findall(r'([0-9.:]+)user\b', my_output)[0]
            system_time = re.findall(r'([0-9.:]+)system\b', my_output)[0]
            elapse_time = re.findall(r'([0-9.:]+)elapsed\b' , my_output)[0]
            cpu = re.findall(r'([0-9.%]+)CPU\b', my_output)[0]

            # print(f"user time {user_time}")
            # print(f"system time {system_time}")
            # print(f"elapse time {elapse_time}")
            # print(f"CPU {cpu}")

            with open(RESULT_ANALYSIS, 'a+') as f:
                f.write(f"{tag}|{d}|{outputfile_json}|{user_time}|{system_time}|{elapse_time}|{cpu}|{profile}\n")


VOLATILITY_DIR="/home/tregua/volatility"
VOLATILITY_PLUGIN_DIR="/home/tregua/sgx-forensic/volatility-plugin/"
DUMP_DIR="/home/tregua/dumps/"
PROFILE_LOCAL="LinuxUbuntu_5_4_0-42-generic_profilex64"
PROFILE_AZURE="LinuxUbuntu_5_4_0-1034-azure_profilex64"

RESULT_DIR=f"{DUMP_DIR}result/"
RESULT_ANALYSIS=f"{RESULT_DIR}analysis-lvl1.txt"


if os.path.exists(RESULT_ANALYSIS):
    print(f"[ERROR] The output file {RESULT_ANALYSIS} already exists, I stop here")
    exit()
else:
    Path(RESULT_ANALYSIS).touch()

# NOT TO ANALYZE
# azure-sgxsdk1.bin
# azure-vm.bin

samples_local = {}
samples_local["sgxrop"] = ["sgxrop.bin"]
samples_local["snakesgx"] = ["snakesgx.bin"]
samples_local["sgxsdk"] = ["sgxsdk-samples.bin"]
samples_local["openenclave"] = ["openenclave-samples.bin"]
samples_local["asylo"] = ["asylo-samples.bin"]
samples_local["graphene"] = ["graphene-samples.bin"]
samples_local["sgxlkl"] = ["sgxlkl-samples-1.bin", "sgxlkl-samples-2.bin", "sgxlkl-samples-3.bin"]
samples_local["rustsgx"] = ["rustsgx-samples.bin"]

samples_azure = {}
samples_azure["conclave"]=["azure-concl.bin"]

run_analysis(samples_local, PROFILE_LOCAL)
run_analysis(samples_azure, PROFILE_AZURE)