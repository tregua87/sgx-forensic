#!/usr/bin/env python3

import sys, os, re, csv, json

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} <analysis-lvl2.txt>")
    exit()

anal2 = sys.argv[1]

all_times = []

with open(anal2) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter='|')

    last_mType = None
    
    for i, row in enumerate(csv_reader):
        latex_row = []

        # detailed file
        detailed_file = row[2]
        with open(detailed_file) as d:
            details = json.load(d)[0]

        mType = details["framework"] 

        if last_mType is None:
            last_mType = mType


        # latex_row = [f"Sample {i}"]

        # latex_row += [details["task_name"]]


        if last_mType != mType:
            print("\midrule")

            f = details["framework"] 
            if f == "sgxsdk":
                latex_row += ["Intel SGX SDK"]
            elif f == "graphene":
                latex_row += ["Graphene"]
            elif f == "rustsdk":
                latex_row += ["Rust SGX SDK"]
            elif f == "openenclave":
                latex_row += ["Open Enclave SDK"]
            elif f == "asylo":
                latex_row += ["Asylo"]
            elif f == "sgxlkl":
                latex_row += ["SGX-LKL"]
            else:
                print(f)
                exit()
        else:
            latex_row += [""]

        if details["encl_type"] == "ELRANGE":
            latex_row += ["API-like"]
        else:
            latex_row += ["Container-like"]

        try:
            latex_row += [f"{len(details['interface'][0]['ecall'])}"]
            latex_row += [f"{len(details['interface'][0]['ocall'])}"]
        except:
            latex_row += ["0"]
            latex_row += ["0"]

        latex_row += [details["encl_flags"].replace("DEBUG,", "")]
        latex_row += [f"{details['encl_ssa_size']}"]

        # analysis time
        latex_row.append(row[5])

        m, s = row[5].split(':')
        all_times += [int(m) * 60 + float(s)]

        # profile
        profile = row[7]
        if "azure" in profile.lower():
            latex_row.append("DCAP")
            latex_row.append("Azure")
        else:
            latex_row.append("isgx")
            latex_row.append("Bare-metal")

        latex_row = [e.replace("_", "\\_").replace("INITIALIZED","INIT").replace("CREATED", "").replace("PROVISION", "PROV") for e in latex_row]




        # if last_mType != mType:
        #     print(" & ".join(latex_row) + " \\\\ \midrule")
        # else:
        #     print(" & ".join(latex_row) + " \\\\")
        print(" & ".join(latex_row) + " \\\\")
        last_mType = mType

print(sum(all_times) / len(all_times))
import statistics
print(statistics.stdev(all_times))
print(statistics.median(all_times))
print(max(all_times))
print(min(all_times))
print(len(all_times))