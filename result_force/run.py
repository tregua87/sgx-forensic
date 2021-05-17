#!/usr/bin/env python3

import sys, os, re, csv, json
import subprocess
from os import listdir
from os.path import isfile, join

RESULTS_FORCE_DIR = "/home/flavio/sgx-forensic/result_force/"
DUMP_DIR = "/home/flavio/dumps"
VOLATILITY_PLUGIN = "/home/flavio/sgx-forensic/volatility-plugin/"
VOLATILITY_DIR = "/home/flavio/volatility/volatility/"

PROFILE_BAREMETAL = "LinuxUbuntu_5_4_0-42-generic_profilex64"
PROFILE_AZURE = "LinuxUbuntu_5_4_0-1034-azure_profilex64"

for f in listdir(DUMP_DIR):
    if isfile(join(DUMP_DIR, f)) and (f.endswith(".zip") or f.endswith(".7z")):

        zipFile = join(DUMP_DIR, f)

        if f.endswith(".zip"):
            bashCommand = f"unzip {zipFile}"
            ext = ".zip"

        if f.endswith(".7z"):
            bashCommand = f"7z x {zipFile}"
            ext = ".7z"

        print(f"[INFO] start decompressing {zipFile}")
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        if process.returncode == 0:
        # if True:

            dump_file = join(RESULTS_FORCE_DIR, f.replace(ext, ""))
            output_file = join(RESULTS_FORCE_DIR, f.replace(ext, "").split("-")[0])

            profile = PROFILE_BAREMETAL
            if "azure" in dump_file.lower():
                print(f"[INFO] change profile to azure")
                profile = PROFILE_AZURE

            print(f"[INFO] analyzing {dump_file}")
            volatility_scan = f"./vol.py --plugins={VOLATILITY_PLUGIN} -f {dump_file} --profile={profile} linux_sgx --force --output=json --output-file={output_file}.json"
            process = subprocess.Popen(volatility_scan.split(), cwd=VOLATILITY_DIR, stdout=subprocess.PIPE)
            output, error = process.communicate()
            # print(output)
            if process.returncode == 0:
                # from IPython import embed; embed(); exit()
                print(f"[INFO] {dump_file} results saved into {output_file}!")
                bashCommand = f"rm -f {dump_file}"
                process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
                output, error = process.communicate()
                print(f"[INFO] {dump_file} deleted!")

        # exit()
        