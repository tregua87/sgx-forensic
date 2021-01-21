#!/usr/bin/env python3

import sys, os, re, csv, json
import subprocess
from pathlib import Path

def run_analysis(tag, dump, pid, ebase, profile):
    global RESULT_DIR
    global VOLATILITY_PLUGIN_DIR
    global VOLATILITY_DIR
    global DUMP_DIR
    global RESULT_ANALYSIS_L2

    dump_name = dump.replace(".bin", "")

    outputfile_json = RESULT_DIR + f"{tag}_{dump_name}_{pid}_{ebase}.json"
    # print(outputfile_json)
    # # from IPython import embed; embed(); exit()
    cmd_str = f"time ./vol.py --plugins={VOLATILITY_PLUGIN_DIR} -f {DUMP_DIR}{dump} --profile={profile} linux_sgx --output=json --output-file={outputfile_json} -p {pid} --ebase 0x{ebase:x}"
    print(cmd_str)
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

    with open(RESULT_ANALYSIS_L2, 'a+') as f:
        f.write(f"{tag}|{dump}|{outputfile_json}|{user_time}|{system_time}|{elapse_time}|{cpu}|{profile}\n")

VOLATILITY_DIR="/home/tregua/volatility"
VOLATILITY_PLUGIN_DIR="/home/tregua/sgx-forensic/volatility-plugin/"
DUMP_DIR="/home/tregua/dumps/"
# PROFILE_LOCAL="LinuxUbuntu_5_4_0-42-generic_profilex64"
# PROFILE_AZURE="LinuxUbuntu_5_4_0-1034-azure_profilex64"

RESULT_DIR=f"{DUMP_DIR}result/"
RESULT_ANALYSIS_L1=f"{RESULT_DIR}analysis-lvl1.txt"
RESULT_ANALYSIS_L2=f"{RESULT_DIR}analysis-lvl2.txt"


if not os.path.exists(RESULT_ANALYSIS_L1):
    print(f"[ERROR] The level 1 file \"{RESULT_ANALYSIS_L1}\" does not already exist, I stop here")
    exit()

# NOT TO ANALYZE
# azure-sgxsdk1.bin
# azure-vm.bin

summary = {}

with open(RESULT_ANALYSIS_L1) as csvfile:
    reader = csv.reader(csvfile, delimiter='|')
    for row in reader:
        tag = row[0]
        dump = row[1]
        json_output = row[2]
        profile = row[7]
        
        print(f"tag {tag} - dump {dump}")

        with open(json_output) as json_file:
            data = json.load(json_file)
            for rowj in data["rows"]:
                proc_name = rowj[1]
                if proc_name != 'aesm_service':
                    pid = rowj[2]
                    ebase = rowj[3]
                    n = summary.get(tag, set())
                    n.add(pid)
                    summary[tag] = n
                    # from IPython import embed; embed(); exit()
                    # print(tag)
                    # print(dump)
                    # print(pid)
                    # print(ebase)
                    # print(profile)
                    run_analysis(tag, dump, pid, ebase, profile)


# for k, p in summary.items():
#     n = len(p)
#     print(f"{k}: {n}")