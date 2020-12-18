# VOLATILITY PLUGIN FOR SGX ANALYSIS ON LINUX
 
The plugin performs a memory and framework analysis on SGX enclaves.  
Requirements:
- First, you have to donwload [Volatility](https://github.com/volatilityfoundation/volatility).
- Second, you should install Radare2 from repository (https://github.com/radareorg/radare2 commit `14f82ee3012e10b56674a01c360ac1fbc4b4bf52`).

Plugin Options:
- FORCE (--force): Force to search SGX enclaves which could use custom SGX kernel drivers
- HIDDENPROC (--hiddenproc, -x): Look for SGX enclaves in hidden processes
- PID (--pid, -p): Operate on this Process ID
- OFFSET (--offset, -o): Operate on this Offset
- EBASE (--ebase): Operate on this Enclave virtual address
- DUMP-DIR (--dump-dir, -D): Output directory for enclaves ELFs
- ANALYSIS (--analysis, -a): Indicate which type of analysis performs over the enclave (I = Interface, M = Memory, B = Both)
- FRAMEWORK (--framework): Force the plugin to use a specific framework strategy to infer the enclave interface <sgxsdk|openenclave|asylo|graphene|sgxlkl|rustsdk>


## Example of use

There are mainly three type of usage of the plugin:

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

```

### Lazy mode

For some examples, just throw `run.sh`.
```bash
./run.sh
```
