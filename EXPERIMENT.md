# How To Replicate the Paper's Experiment

This is an guide to replicate the paper's experiment.

In particular, this guide will focus on the following aspects:
1. [System setup](#system-setup)
2. [Get the repositories and commit version to use](#repositories)
3. [Run the steps](#run-the-steps)

## System Setup

- The machine must support SGX (or find an VM on Azure, Gen 2 https://portal.azure.com/)
- Install an Ubuntu 18.04
- Compile LiME ([here](./lime/README.md))
    - To succesfully use our LiME ([here](./lime/README.md)) set `nokaslr` in kernel (more info [here](https://askubuntu.com/questions/19486/how-do-i-add-a-kernel-boot-parameter)).
    - For Azure VM, you have to set `nokaslr` anytime the VM boots (in GRUB, [here](https://docs.microsoft.com/en-us/troubleshoot/azure/virtual-machines/serial-console-linux))
- Install the Intel Drivers
    - If you have a bare metal machine (e.g., a laptop), probably you just need the legacy drivers ([here](https://github.com/intel/linux-sgx-driver)). We used version `2.11.0` but any version should go
    - If you have an Azure VM, you should go for the new DCAP drivers ([here](https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-dcap-1.6-release)). We used version `1.33`
- Install Volatility, our plugin, and the relative dependences ([here](./volatility-plugin/README.md))
- Get the Volatilify Overlay ([here](./volatility-module/README.md)). This allows Volatility to analyse your Linux Version (we tested on Ubuntu, as said before)


## Repositories

For each of the following repository, we installed the framework and checked their examples work. Each work is a world apart, we recommend to check each single repository for more detail.

**NOTE:** for a cleaner (and more succesful) execution, we suggest you install one framework at the time, run dump/experiments, and pass to the next framework. This especially if yo are not familiar with SGX.

| Sample Source | Link | Version/Commit | Note |
| - | - | -: | - |
| Intel SGX SDK | https://github.com/intel/linux-sgx | A4F0C86828443EBB | 
| Open Enclave SDK | https://github.com/openenclave/openenclave | E32E10AC73C56F5B |
| Asylo | https://github.com/google/asylo | 5E19B541673A9C19 |
| Graphene | https://github.com/gramineproject/graphene.git | DCE0E6FD1751091D |
| SGX-LKL | https://github.com/lsds/sgx-lkl | F20210CEB1339EA1 | SGX-LKL associates a single virtual interface to each application, so you can't run multiple app in parallel
| RUST-SGX | https://github.com/apache/incubator-teaclave-sgx-sdk | 3E2E19052F589BFB | Compiled w/ Open Enclave support
| Conclave | https://conclave.net/get-conclave/ | 0.4 | Contact R3 to get the same version
| SGX-ROP | https://github.com/IAIK/sgxrop | 8086F6E624B0A43E |
| SnakeGX | https://github.com/tregua87/snakegx | D4E69C20ACD700A7 | |

## Run the steps

- We assume you have an SGX application from any of the above repo
- For simplicity, we consider the classic `SampleEnclave` ([here](https://github.com/intel/linux-sgx/tree/master/SampleCode/SampleEnclave)), but the same approach can be replicated to any application from the other frameworks
    - To ensure the enclave is in memory, the simplest trick is to add a `getchar()` before `sgx_destroy_enclave()` ([here](https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleEnclave/App/App.cpp#L204))
- While application is running, run LiME ([here](./lime/README.md)) to dump the memory

Give an machine image in a given location, we can run the following analyses with our plugin as decribed below (a copy from [here](./volatility-plugin/README.md)).

```bash
IMAGE_DUMP=$HOME/sgx-forensic/lime/src/hello-openenclave.bin
```

### 1) List of the SGX Enclaves in the system

No options, the plugin shows SGX system info related, and lists all processes that contains SGX enclaves.
You can use `FORCE` or `HIDDENPROC` for a deeper reserach (but it is slower).

```bash
PLUGIN_DIR=$HOME/sgx-forensic-2/volatility-plugin/
# NOTE: replace with real dump path
IMAGE_DUMP=$HOME/sgx-forensic/lime/src/hello-openenclave.bin
cd ~/volatility
./vol.py --plugins="$PLUGIN_DIR" -f $IMAGE_DUMP$ --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx
```

Output:
```
Volatility Foundation Volatility Framework 2.6.1
SGX EPC banks:
        INT0E0C:00      0x40200000 - 0x45f7ffff
SGX module banner: Intel SGX Driver v2.11.0
Intel SGX driver loaded: isgx
Offset             Process      PID  Enclave base     Enclave size Enclave flags                         
0xffff88840b7217c0 app          3707   0x7f4f41000000 0x1000000    DEBUG,INITIALIZED,MODE_64BIT          
0xffff88844716df00 aesm_service 2304   0x7f0345b00000 0x100000     EINIT_TOKEN_KEY,INITIALIZED,MODE_64BIT
0xffff888472444740 aesm_service 1028   0x7f877b400000 0x100000     EINIT_TOKEN_KEY,INITIALIZED,MODE_64BIT
```

### 2) Deep analysis of a specific enclave

Focus the analysis on a specific SGX Enclave. You can use `PID` or `OFFEST` to indicate the process, and `EBASE` to indicate the enclave in that process.
The plugin implements two analysis, that can be tuned with option `ANALYSIS`:
- Memory Analysis (i.e., `-a M`): look for patterns in the enclave memory.
- Interface Analysis (i.e., `-a I`): look for interface information in the enclave. You can further indicate the SDX framework used with the option `FRAMEWORK`.
- Both memory and interface analysis (i.e., `-a B`, or default behavior): the plugin performs both memory and interface analysis.

If the main ELF differs from the one located by Volatility (e.g., it happens for Java applications, but not only), you can manually indicate the main ELF base address through `MAINELF` (e.g, `--mainelf 0x7fb1a248d000`).

```bash
PLUGIN_DIR=$HOME/sgx-forensic-2/volatility-plugin/
# NOTE: replace with real dump path
IMAGE_DUMP=$HOME/sgx-forensic/lime/src/hello-openenclave.bin
cd ~/volatility
./vol.py --plugins="$PLUGIN_DIR" -f $IMAGE_DUMP$ --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 2304 --ebase  0x7f0345b00000
```

Output:
```
Volatility Foundation Volatility Framework 2.6.1
SGX EPC banks:
        INT0E0C:00      0x40200000 - 0x45f7ffff
SGX module banner: Intel SGX Driver v2.11.0
Intel SGX driver loaded: isgx
Look for interface information... very slow!

================================================================================
Host Process [offset=0xffff88840b7217c0, name=app, PID: 3707]
Enclave [base_address=0x7f4f41000000, size=0x1000000, flags=DEBUG,INITIALIZED,MODE_64BIT, xfrm=0x7, ssa size=1 type=ELRANGE]
TCS: 0x7f4f417aa000 0x7f4f41736000 0x7f4f416c2000 0x7f4f4164e000 0x7f4f415da000 0x7f4f41566000 0x7f4f414f2000 0x7f4f4147e000 0x7f4f4140a000 0x7f4f41396000
Memory Layout:
        0x7f4f41000000-0x7f4f41026000 r-x [CODE]
        0x7f4f41026000-0x7f4f41225000 ---
        0x7f4f41225000-0x7f4f41226000 r-- [CONSTANT]
        0x7f4f41226000-0x7f4f41336000 rw- [GLOBAL]
        0x7f4f41336000-0x7f4f41346000 ---
        0x7f4f41346000-0x7f4f41386000 rw- [STACK]
        0x7f4f41386000-0x7f4f41396000 ---
        0x7f4f41396000-0x7f4f41399000 rw- [TCSSSA]
        0x7f4f41399000-0x7f4f413a9000 ---
        0x7f4f413a9000-0x7f4f413aa000 rw- [TLS]
....
        0x7f4f4175a000-0x7f4f4179a000 rw- [STACK]
        0x7f4f4179a000-0x7f4f417aa000 ---
        0x7f4f417aa000-0x7f4f417ad000 rw- [TCSSSA]
        0x7f4f417ad000-0x7f4f417bd000 ---
        0x7f4f417bd000-0x7f4f417be000 rw- [TLS]
        0x7f4f417be000-0x7f4f42000000 ---
SGX Framework: sgxsdk
ECREATE: 0x55bb61bed32c
ECALL: 0x55bb61bece82 0x55bb61bec784 0x55bb61bec98b 0x55bb61becd8d 0x55bb61beca15 0x55bb61bed116 0x55bb61becfd9 0x55bb61becd1f 0x55bb61bece20 0x55bb61becfa8 0x55bb61bec8aa 0x55bb61beccb1 0x55bb61bed1b9 0x55bb61bec71f 0x55bb61becdbe 0x55bb61becbbf 0x55bb61bec6c0 0x55bb61bec920 0x55bb61becc43 0x55bb61becf46 0x55bb61bed147 0x55bb61bed049 0x55bb61bec84b 0x55bb61becad9 0x55bb61bec65e 0x55bb61becb3b 0x55bb61becee4 0x55bb61bed0e5 0x55bb61bec7e9 0x55bb61bed1ea 0x55bb61beca77 0x55bb61bed07a
OCALL: 0x55bb61bec620 0x55bb61bec542 0x55bb61bec4c8 0x55bb61bec57c 0x55bb61bec44a 0x55bb61bec5e2 0x55bb61bec5af 0x55bb61bec4f2 0x55bb61bec474 0x55bb61bec51c 0x55bb61bec49e
```

### 3) Dump of enclave content (if in DEBUG)

This is like the previous one, but you further indicate `DUMP-DIR` to the dump location.

```bash
PLUGIN_DIR=$HOME/sgx-forensic-2/volatility-plugin/
# NOTE: replace with real dump path
IMAGE_DUMP=$HOME/sgx-forensic/lime/src/hello-openenclave.bin
cd ~/volatility
./vol.py --plugins="$PLUGIN_DIR" -f $IMAGE_DUMP$ --profile=LinuxUbuntu_5_4_0-42-generic_profilex64 linux_sgx -p 2304 --ebase  0x7f0345b00000 -D $TMP/tmp
