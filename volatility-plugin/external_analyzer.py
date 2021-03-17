import r2pipe, sys
from subprocess import Popen, PIPE, STDOUT

class ExternalAnalyzerSGXSDK:

    @staticmethod
    def _look_reloc_symbol(bf, reloc_symbol):

        for f in bf.cmdj("aflj"):
            name = f["name"]
            typ = f["type"]
            minbound = f["minbound"]
            maxbound = f["maxbound"]
            offset = f["offset"]

            pdfj = bf.cmdj("pdfj @ {}".format(name))

            if not pdfj:
                continue

            # only one opcode
            if len(pdfj["ops"]) != 1:
                continue

            op = pdfj["ops"][0]

            # the only opcode is a "jmp qword"
            if not op["disasm"].startswith("jmp qword"):
                continue

            # u'disasm': u'jmp qword [reloc.sgx_ecall]',
            # the jmp has to point to the symbol
            if reloc_symbol in op["disasm"]:
                return offset

        return None

    @staticmethod 
    def extract_interface(elfs_maps, ocall_table):

        file_main_elf = None
        base_addr = None
        for k, v in elfs_maps.iteritems():
            if v["main"]:
                file_main_elf = v["file_path"]
                base_addr = v["vm_start"]
                break

        if not file_main_elf:
            print("Cannot find main ELF")
            exit()

        ocall_table_norm = [o-base_addr for o in ocall_table]

        # ocall_table_confirmed = set()
        # ecalls = set()
        ecreates = set()
        pair_ecall_ocall_table_raw = set()


        # stdout_old = sys.stdout
        # stderr_old = sys.stderr
        # f = open('/dev/null', 'w')
        # sys.stdout = f
        # sys.stderr = f
        # try:

        # from IPython import embed; embed(); exit()
        bf = r2pipe.open(file_main_elf, ["-2"])
        bf.cmd("aaaaaa")

        # is that better?
        bf.cmd("aab")
        bf.cmd("aav")

        # search for symbol sgx_ecall
        sgx_ecall_sym = [f for f in bf.cmdj("aflj") if f["name"] == "sym.imp.sgx_ecall"]
        sgx_ecall_add = None
        if sgx_ecall_sym:
            sgx_ecall_add = sgx_ecall_sym[0]["offset"]
        else:
            sgx_ecall_add = ExternalAnalyzerSGXSDK._look_reloc_symbol(bf, "reloc.sgx_ecall")

        # print("sgx_ecall_add 0x{:x}".format(sgx_ecall_add))

        # search for symbol sgx_ecall_switchless
        sgx_ecall_sw_sym = [f for f in bf.cmdj("aflj") if f["name"] == "sym.imp.sgx_ecall_switchless"]
        sgx_ecall_sw_add = None
        if sgx_ecall_sw_sym:
            sgx_ecall_sw_add = sgx_ecall_sw_sym[0]["offset"]
        else:
            sgx_ecall_sw_add = ExternalAnalyzerSGXSDK._look_reloc_symbol(bf, "reloc.sgx_ecall_switchless")

        # search for symbol sgx_create_enclave
        sgx_create_sym = [f for f in bf.cmdj("aflj") if f["name"] == "sym.imp.sgx_create_enclave"]
        sgx_create_add = None
        if sgx_create_sym:
            sgx_create_add = sgx_create_sym[0]["offset"]
        else:
            sgx_ecall_sw_add = ExternalAnalyzerSGXSDK._look_reloc_symbol(bf, "reloc.sgx_ecreate")

        # print("new trick?")
        # from IPython import embed; embed(); exit()

        # print("sgx_ecall_add 0x{:x}".format(sgx_ecall_add))
        # print("sgx_ecall_sw_add 0x{:x}".format(sgx_ecall_sw_add))
        # print("sgx_create_add 0x{:x}".format(sgx_create_add))

        for f in bf.cmdj("aflj"):
            # from IPython import embed; embed()
            # typ = f["type"]

            # just functions
            # if typ == "fcn":
            # from IPython import embed; embed(); exit()
            name = f["name"]
            # print(name)
            # if name == "sym.jvm_ecall":
            #     from IPython import embed; embed(); exit()
            minbound = f["minbound"]
            maxbound = f["maxbound"]

            # if name == "fcn.000028a5":
            # print(f"{typ} {name} 0x{minbound:02x} 0x{maxbound:02x}")
            bf.cmd("s {}".format(name))
            pdfj = bf.cmdj("pdfj")

            if pdfj:
                has_ocall_optr = 0
                has_call_sgxecall = False
                has_call_sgxecallsw = False
                has_call_sgxcreate = False
                for o in pdfj["ops"]:
                    if "ptr" in o and o["ptr"] in ocall_table_norm:
                        has_ocall_optr = ocall_table[ocall_table_norm.index(o["ptr"])]
                    
                    if "jump" in o and o["jump"] == sgx_ecall_add:
                        has_call_sgxecall = True

                    if "jump" in o and o["jump"] == sgx_ecall_sw_add:
                        has_call_sgxecallsw = True

                    if "jump" in o and o["jump"] == sgx_create_add:
                        has_call_sgxcreate = True

                if has_call_sgxecall and (not ocall_table_norm or has_ocall_optr):
                    # print("[ECALL] {} | ocall_table @ 0x{:02x}".format(name, has_ocall_optr))
                    # ocall_table_confirmed.add(has_ocall_optr)
                    # ecalls.add(minbound + base_addr)
                    pair_ecall_ocall_table_raw.add((minbound + base_addr, has_ocall_optr))

                if has_call_sgxecallsw and (not ocall_table_norm or has_ocall_optr):
                    # print("[ECALL SWITCHLESS] {} | ocall_table @ 0x{:02x}0".format(name, has_ocall_optr))
                    # ocall_table_confirmed.add(has_ocall_optr)
                    # ecalls.add(minbound + base_addr)
                    pair_ecall_ocall_table_raw.add((minbound + base_addr, has_ocall_optr))

                if has_call_sgxcreate:
                    ecreates.add(minbound + base_addr)

        # print(pair_ecall_ocall_table_raw)

        pair_ecall_ocall_table = []
        
        ocall_table_last = None
        ecall_set = set()
        for i, (ecall, ocall_table) in enumerate(sorted(pair_ecall_ocall_table_raw, key=lambda el: el[1])):
            
            # print(i)
            # print(pair_ecall_ocall_table)
            # print("{} {}".format(ecall, ocall_table))
            # print("ocall last {}".format(ocall_table_last))

            if ocall_table_last is None:
                ocall_table_last = ocall_table
                ecall_set = set()

            if ocall_table_last != ocall_table:
                pair_ecall_ocall_table.append((list(ecall_set), ocall_table_last))

                ocall_table_last = ocall_table
                ecall_set = set()

            ecall_set.add(ecall)

        pair_ecall_ocall_table.append((list(ecall_set), ocall_table))
            

        # return [ecreate], [ecalls], [ocalls]
        return ecreates, pair_ecall_ocall_table

class ExternalAnalyzerOE:

    @staticmethod 
    def extract_interface(elfs_maps, possible_ocall_table, possible_ocall_table_size, possible_ecall_table_content):

        file_main_elf = None
        base_addr = None
        for k, v in elfs_maps.iteritems():
            if v["main"]:
                file_main_elf = v["file_path"]
                base_addr = v["vm_start"]
                break

        if not file_main_elf:
            print("Cannot find main ELF")
            exit()

        ocall_table_norm = [o-base_addr for o in possible_ocall_table]
        ocall_table_confirmed = list()
        ocall_table_size_confirmed = list()

        possible_ecall_table = []
        possible_ecall_table_size = []
        for ec, ec_cnt in possible_ecall_table_content.iteritems():
            possible_ecall_table += [ec]
            possible_ecall_table_size += [len(ec_cnt)]

        ecall_table_norm = [e-base_addr for e in possible_ecall_table]
        # ecall_table_confirmed = list()
        # ecall_table_size_confirmed = list()

        # ecalls = []
        ecreates = []
        pair_ecall_ocalltable_ocalltablesize_raw = set()

        bf = r2pipe.open(file_main_elf, ["-2"])
        bf.cmd("aaaaaa")

        # search for create enclave
        for f in bf.cmdj("aflj"):
            name = f["name"]
            typ = f["type"]
            minbound = f["minbound"]
            maxbound = f["maxbound"]

            # print(name)
            # continue

            if typ == "fcn":
                bf.cmd("s {}".format(name))
                pdfj = bf.cmdj("pdfj")
                has_ocall_ptr = 0
                has_ecall_ptr = 0

                if pdfj is not None:

                    for o in pdfj["ops"]:
                        if "ptr" in o and o["ptr"] in ocall_table_norm:
                            # print("ocall side")
                            # print(o)
                            has_ocall_ptr = possible_ocall_table[ocall_table_norm.index(o["ptr"])]
                        
                        if "ptr" in o and o["ptr"] in ecall_table_norm:
                            # print("ecall side")
                            # print(o)
                            has_ecall_ptr = possible_ecall_table[ecall_table_norm.index(o["ptr"])]
                        

                    if has_ocall_ptr and has_ecall_ptr:
                        # print("[ECREATE] {} | ocall_table @ 0x{:02x} ecall_table @ 0x{:02x}".format(name, has_ocall_ptr, has_ecall_ptr))
                        # from IPython import embed; embed(); exit()

                        ocall_table_size = possible_ocall_table_size[possible_ocall_table.index(has_ocall_ptr)]

                        pair_ecall_ocalltable_ocalltablesize_raw.add((has_ecall_ptr, has_ocall_ptr, ocall_table_size))

                        # ocall_table_confirmed += [has_ocall_ptr]
                        # ocall_table_size_confirmed += [possible_ocall_table_size[possible_ocall_table.index(has_ocall_ptr)] ]
                        # ecall_table_confirmed += [has_ecall_ptr]
                        # ecall_table_size_confirmed += [possible_ecall_table_size[possible_ecall_table.index(has_ecall_ptr)] ]
                        ecreates += [f["offset"] + base_addr]

        # ecall_info_str_flat = set()
        # for ec in ecall_table_confirmed:
        #     for ptr in possible_ecall_table_content[ec]:
        #         ecall_info_str_flat.add(ptr-base_addr)

        pair_ecall_ocalltable_ocalltablesize = []

        ocall_table_last = None
        ocall_table_size_last = 0
        ecall_set = set()
        ocall_table = None
        ocall_table_size = 0
        for i, (ecall_token_table, ot, ots) in enumerate(sorted(pair_ecall_ocalltable_ocalltablesize_raw, key=lambda el: el[1])):

            ocall_table_size = ots
            ocall_table = ot
            
            # print(i)
            # print(pair_ecall_ocall_table)
            # print("{} {}".format(ecall, ocall_table))
            # print("ocall last {}".format(ocall_table_last))

            if ocall_table_last is None:
                ocall_table_last = ocall_table
                ocall_table_size_last = ocall_table_size
                ecall_set = set()

            if ocall_table_last != ocall_table:
                pair_ecall_ocalltable_ocalltablesize.append((list(ecall_set), ocall_table_last, ocall_table_size_last))

                ocall_table_last = ocall_table
                ocall_table_size_last = ocall_table_size
                ecall_set = set()

            ecall_info_str_flat = set()
            for ptr in possible_ecall_table_content[ecall_token_table]:
                ecall_info_str_flat.add(ptr-base_addr)

             # search for ecall enclave
            for f in bf.cmdj("aflj"):
                name = f["name"]
                typ = f["type"]
                minbound = f["minbound"]
                maxbound = f["maxbound"]
                fun_addr = f["offset"] + base_addr

                # print(name)
                # continue

                if typ == "fcn":
                    bf.cmd("s {}".format(name))
                    pdfj = bf.cmdj("pdfj")
                    if pdfj:
                        has_ecall_info_ptr = False

                        for o in pdfj["ops"]:
                            if "ptr" in o and o["ptr"] in ecall_info_str_flat and "esil" in o and "rdx" in o["esil"]:
                                has_ecall_info_ptr = True
                                break

                        if has_ecall_info_ptr:
                            # print("[ECALL] 0x{:02x}".format(fun_addr))
                            ecall_set.add(fun_addr)

        pair_ecall_ocalltable_ocalltablesize.append((list(ecall_set), ocall_table, ocall_table_size))

        return ecreates, pair_ecall_ocalltable_ocalltablesize
        # return ecreates, ecalls, ocall_table_confirmed, ocall_table_size_confirmed

class ExternalAnalyzerASYLO:

    @staticmethod 
    def extract_interface(elfs_maps):

        file_main_elf = None
        base_addr = None
        for k, v in elfs_maps.iteritems():
            if v["main"]:
                file_main_elf = v["file_path"]
                base_addr = v["vm_start"]
                break

        if not file_main_elf:
            print("Cannot find main ELF")
            exit()

        ecalls = []

        bf = r2pipe.open(file_main_elf)
        bf.cmd("aaaaaa")

        # from IPython import embed; embed()
        # serach for enclu
        for f in bf.cmdj("/ad/j enclu"):
            # print(f)

            offset = f["offset"]

            # {'offset': 4794775, 'len': 3, 'code': 'enclu'}
            # from IPython import embed; embed()
            seek_rax = False
            is_eenter = False
            f_addr = None
            
            # from IPython import embed; embed()
            pdf_res = None
            try:
                pdf_res = bf.cmdj("pdfj @ 0x{:02x}".format(offset))
            except:
                pass

            if pdf_res is not None:
                for c in reversed(pdf_res["ops"]):
                    disasm = c["disasm"]
                    c_offset = c["offset"]

                    if c_offset == offset:
                        seek_rax = True

                    if f_addr is None:
                        f_addr = c["fcn_addr"]

                    if seek_rax:
                        #  {'offset': 4794768,
                        # 'val': 2,
                        # 'esil': '2,rax,=',
                        # 'refptr': False,
                        # 'fcn_addr': 4794616,
                        # 'fcn_last': 4794870,
                        # 'size': 7,
                        # 'opcode': 'mov rax, 2',
                        # 'disasm': 'mov rax, 2',
                        # 'bytes': '48c7c002000000',
                        # 'family': 'cpu',
                        # 'type': 'mov',
                        # 'reloc': False,
                        # 'type_num': 9,
                        # 'type2_num': 0},
                        if disasm.startswith("mov rax,") and c["val"] == 0x2:
                            is_eenter = True
                            break

                f_addr += base_addr

                # I found a function containing an EENTER
                if is_eenter:
                    print("[INFO] function @ 0x{:02x} does EENTER".format(f_addr))
                else:
                    print("[INFO] function @ 0x{:02x} has an ENCLU".format(f_addr))

                ecalls += [f_addr]

        return ecalls

class ExternalAnalyzerGRAPHENE:

    @staticmethod 
    def extract_interface(elfs_maps, possible_ocall_table, possible_ocall_table_size):
        file_main_elf = None
        base_addr = None
        for k, v in elfs_maps.iteritems():
            if v["main"]:
                file_main_elf = v["file_path"]
                base_addr = v["vm_start"]
                break

        if not file_main_elf:
            print("Cannot find main ELF")
            exit()

        ecalls = set()

        ocall_table_norm = [o-base_addr for o in possible_ocall_table]
        ocall_table_confirmed = list()
        ocall_table_size_confirmed = list()

        bf = r2pipe.open(file_main_elf, ["-2"])
        bf.cmd("aaaaaa")

        # is that better?
        bf.cmd("aab")
        bf.cmd("aav")

        # search for ecall (or generic entry points)
        for f in bf.cmdj("/ad/j enclu"):
            # print(f)

            offset = f["offset"]

            # print("[INFO] something @ 0x{:02x}".format(offset))

            # {'offset': 4794775, 'len': 3, 'code': 'enclu'}
            # from IPython import embed; embed()
            f_addr = None
            
            # from IPython import embed; embed()
            pdf_res = None
            try:
                pdf_res = bf.cmdj("pdfj @ 0x{:02x}".format(offset))
            except:
                pass

            if pdf_res is not None:
                f_addr = pdf_res["addr"]
                
                ecalls.add(f_addr + base_addr)

        # for f in ecalls:
        #     print("[INFO] function @ 0x{:02x} does EENTER".format(f))

        # search for dispatch ocall
        for f in bf.cmdj("aflj"):
            name = f["name"]
            typ = f["type"]
            minbound = f["minbound"]
            maxbound = f["maxbound"]
            
            # if "fcn.30a0" in name:
            #     print("is")
            #     from IPython import embed; embed()
            #     exit()

            pdfj = bf.cmdj("pdfj @ {}".format(name))
            
            if pdfj is None:
                continue
            has_ocall_ptr = 0
            
            for o in pdfj["ops"]:
                # print(o["disasm"])
                # from IPython import embed; embed()
                # original!
                # if "disasm" in o and o["disasm"].startswith("lea r9") and "ptr" in o and o["ptr"] in ocall_table_norm:
                #     # print("ocall side")
                #     # print(o)
                #     has_ocall_ptr = possible_ocall_table[ocall_table_norm.index(o["ptr"])]
                if "disasm" in o and o["disasm"].startswith("lea") and "ptr" in o and o["ptr"] in ocall_table_norm:
                    # print("ocall side")
                    # print(o)
                    has_ocall_ptr = possible_ocall_table[ocall_table_norm.index(o["ptr"])]
                

            if has_ocall_ptr:
                # print("[OCALL DISPATCH] {} | ocall_table @ 0x{:02x}".format(name, has_ocall_ptr))
                ocall_table_confirmed += [has_ocall_ptr]
                ocall_table_size_confirmed += [possible_ocall_table_size[possible_ocall_table.index(has_ocall_ptr)] ]

        return ecalls, ocall_table_confirmed, ocall_table_size_confirmed

class ExternalAnalyzerSGXLKL:

    @staticmethod 
    def extract_interface(elfs_maps, possible_ocall_table, possible_ocall_table_size):
        file_main_elf = None
        base_addr = None
        for k, v in elfs_maps.iteritems():
            if v["main"]:
                file_main_elf = v["file_path"]
                base_addr = v["vm_start"]
                break

        if not file_main_elf:
            print("Cannot find main ELF")
            exit()

        ocall_table_norm = possible_ocall_table # [o-base_addr for o in possible_ocall_table]
        ocall_table_confirmed = list()
        ocall_table_size_confirmed = list()

        ecreate = []

        bf = r2pipe.open(file_main_elf, ["-2"])
        bf.cmd("aaaaaa")

        # search for create enclave
        for f in bf.cmdj("aflj"):
            name = f["name"]
            typ = f["type"]
            minbound = f["minbound"]
            maxbound = f["maxbound"]
            offset = f["offset"]

            bf.cmd("s {}".format(name))

            pdfj = bf.cmdj("pdfj")
            
            if pdfj is None:
                continue
            has_ocall_ptr = 0
            
            for o in pdfj["ops"]:
                # print(o["disasm"])
                # from IPython import embed; embed()
                if "disasm" in o and o["disasm"].startswith("lea r9") and "ptr" in o and o["ptr"] in ocall_table_norm:
                    # print("ocall side")
                    # print(o)
                    has_ocall_ptr = possible_ocall_table[ocall_table_norm.index(o["ptr"])]
                

            if has_ocall_ptr:
                # print("[ECREATE] {} | ocall_table @ 0x{:02x}".format(name, has_ocall_ptr))
                ecreate += [offset]

                ocall_table_confirmed += [has_ocall_ptr]
                ocall_table_size_confirmed += [possible_ocall_table_size[possible_ocall_table.index(has_ocall_ptr)] ]

        ecalls = set()

        for f in bf.cmdj("/ad/j enclu"):
            # print(f)

            offset = f["offset"]

            # {'offset': 4794775, 'len': 3, 'code': 'enclu'}
            # from IPython import embed; embed()
            seek_rax = False
            is_eenter = False
            f_addr = None
            
            # from IPython import embed; embed()
            pdf_res = None
            try:
                pdf_res = bf.cmdj("pdfj @ 0x{:02x}".format(offset))
            except:
                pass

            if pdf_res is not None:
                o = pdf_res["ops"][0]
                f_addr = o["fcn_addr"]
                
                ecalls.add(f_addr)

        # for f in ecalls:
        #     print("[INFO] function @ 0x{:02x} does EENTER".format(f))

        return ecreate, ecalls, ocall_table_confirmed, ocall_table_size_confirmed

class ExternalAnalyzerRUSTSDK:
    @staticmethod 
    def extract_pltjmp(elfs_maps):

        file_main_elf = None
        base_addr = None
        for k, v in elfs_maps.iteritems():
            if v["main"]:
                file_main_elf = v["file_path"]
                base_addr = v["vm_start"]
                break

        if not file_main_elf:
            print("Cannot find main ELF")
            exit()

        bf = r2pipe.open(file_main_elf, ["-2"])
        bf.cmd("aaaaaa")

        # is that better?
        bf.cmd("aab")
        bf.cmd("aav")

        pltjmp = {}

        for f in bf.cmdj("aflj"):
            name = f["name"]
            typ = f["type"]
            minbound = f["minbound"]
            maxbound = f["maxbound"]
            offset = f["offset"]

            pdfj = bf.cmdj("pdfj @ {}".format(name))

            if not pdfj:
                continue

            # only one opcode
            if len(pdfj["ops"]) != 1:
                continue

            op = pdfj["ops"][0]

            # the only opcode is a "jmp qword"
            if not op["disasm"].startswith("jmp qword"):
                continue
            
            ptr = op["ptr"]

            # print("{} @ 0x{:x} -> 0x{:x}".format(name, offset, ptr))

            pltjmp[offset] = ptr + base_addr

            # if name == "fcn.00023d80":
            #     from IPython import embed; embed(); exit()

            # I AM LOOKING FOR THESE GUYS!
            #  6: fcn.000063b0 ();
            #  bp: 0 (vars 0, args 0)
            #  sp: 0 (vars 0, args 0)
            #  rg: 0 (vars 0, args 0)
            #            0x000063b0      ff2502842400   jmp qword [0x0024e7b8]      ; [0x24e7b8:8]=0x55e40d832717

        return pltjmp

    @staticmethod 
    def extract_exported_fun(elfs_maps, lib_name):
        # get libsgx_urts.so base address
        lib_ba = None
        file_lib = None
        for k, v in elfs_maps.iteritems():
            if lib_name in k:
                file_lib = v["file_path"]
                lib_ba = v["vm_start"]
                break

        if lib_ba is None:
            print("[ERROR] '{}' not found!".format(lib_name))
            exit()

        # print(file_lib)

        bf = r2pipe.open(file_lib, ["-2"])
        bf.cmd("aaaaaa")

        # is that better?
        bf.cmd("aab")
        bf.cmd("aav")

        exported_fun = {}
        # from IPython import embed; embed()

        # get exported symbol (!= imp.*)
        for s in bf.cmdj("isj"):

            typ = s["type"]   # u'type': u'FUNC'
            bind = s["bind"]  # u'bind': u'GLOBAL',
            is_imported = s["is_imported"] # False ?
            vaddr = s["vaddr"]
            name = s["name"]

            if typ == "FUNC" and bind == "GLOBAL" and not is_imported:
                exported_fun[vaddr] = name

        return exported_fun

    @staticmethod 
    def extract_interface(elfs_maps, possible_ocall_table, plt_decoded):
        
        file_main_elf = None
        base_addr = None
        for k, v in elfs_maps.iteritems():
            if v["main"]:
                file_main_elf = v["file_path"]
                base_addr = v["vm_start"]
                break

        if not file_main_elf:
            print("Cannot find main ELF")
            exit()
        

        ocall_table_norm = [o-base_addr for o in possible_ocall_table]

        # ocall_table_confirmed = set()
        # ecalls = set()
        pair_ecall_ocall_table_raw = []

        # from IPython import embed; embed(); exit()
        bf = r2pipe.open(file_main_elf, ["-2"])
        bf.cmd("aaaaaa")

        # is that better?
        bf.cmd("aab")
        bf.cmd("aav")

        # # rename functions
        # for f in bf.cmdj("aflj"):
        #     offset = f["offset"]

        #     if offset in plt_decoded:
        #         # rename function at address
        #         f_name = plt_decoded[offset]
        #         bf.cmd("afn {} {}".format(f_name, offset))

        sgx_ecall_add = None
        sgx_ecall_sw_add = None
        for addr, f_name in plt_decoded.iteritems():
            if f_name == "sgx_ecall":
                sgx_ecall_add = addr
            if f_name == "sgx_ecall_switchless":
                sgx_ecall_sw_add = addr

        # print("before aflj")

        for f in bf.cmdj("aflj"):
            # from IPython import embed; embed()
            typ = f["type"]

            # just functions
            if typ == "fcn":
                # from IPython import embed; embed(); exit()
                name = f["name"]
                # print(name)
                # from IPython import embed; embed()
                minbound = f["minbound"]
                maxbound = f["maxbound"]

                # if name == "fcn.000028a5":
                # print(f"{typ} {name} 0x{minbound:02x} 0x{maxbound:02x}")
                bf.cmd("s {}".format(name))
                pdfj = bf.cmdj("pdfj")

                if pdfj is not None:
                    has_ocall_optr = 0
                    has_call_sgxecall = False
                    has_call_sgxecallsw = False
                    has_call_sgxcreate = False
                    for o in pdfj["ops"]:
                        if "ptr" in o and o["ptr"] in ocall_table_norm:
                            has_ocall_optr = possible_ocall_table[ocall_table_norm.index(o["ptr"])]
                        
                        if "jump" in o and o["jump"] == sgx_ecall_add:
                            has_call_sgxecall = True

                        if "jump" in o and o["jump"] == sgx_ecall_sw_add:
                            has_call_sgxecallsw = True

                    if has_call_sgxecall and has_ocall_optr:
                        # print("[ECALL] {} | ocall_table @ 0x{:02x}".format(name, has_ocall_optr))
                        pair_ecall_ocall_table_raw.append((minbound + base_addr, has_ocall_optr))
                        # ocall_table_confirmed.add(has_ocall_optr)
                        # ecalls.add(minbound + base_addr)

                    if has_call_sgxecallsw and has_ocall_optr:
                        # print("[ECALL SWITCHLESS] {} | ocall_table @ 0x{:02x}0".format(name, has_ocall_optr))
                        pair_ecall_ocall_table_raw.append((minbound + base_addr, has_ocall_optr))
                        # ocall_table_confirmed.add(has_ocall_optr)
                        # ecalls.add(minbound + base_addr)

        # print("before sorted loop")

        pair_ecall_ocall_table = []
        
        ocall_table_last = None
        ecall_set = set()
        for ecall, ocall_table in sorted(pair_ecall_ocall_table_raw, key=lambda el: el[1]):
            
            # print(i)
            # print(pair_ecall_ocall_table)
            # print("{} {}".format(ecall, ocall_table))
            # print("ocall last {}".format(ocall_table_last))

            if ocall_table_last is None:
                ocall_table_last = ocall_table
                ecall_set = set()

            if ocall_table_last != ocall_table:
                pair_ecall_ocall_table.append((list(ecall_set), ocall_table_last))

                ocall_table_last = ocall_table
                ecall_set = set()

            ecall_set.add(ecall)

        try:
            pair_ecall_ocall_table.append((list(ecall_set), ocall_table))
        except:
            pass

        # return [ecalls], [ocalls]
        return pair_ecall_ocall_table

class ExternalAnalyzerFINGERPRINT:

    @staticmethod
    def _get_string(elfs_map):
        file_lib = None
        lib_ba = None
        for k, v in elfs_map.iteritems():
            if v["main"]:
                file_lib = v["file_path"]
                lib_ba = v["vm_start"]
                break

        cmd = 'strings {}'.format(file_lib)
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        output = p.stdout.read()
        return output.split()

    @staticmethod
    def _get_imported_functions(elfs_map):
        file_lib = None
        lib_ba = None
        for k, v in elfs_map.iteritems():
            if v["main"]:
                file_lib = v["file_path"]
                lib_ba = v["vm_start"]
                break

        if lib_ba is None:
            print("[ERROR] '{}' not found!".format(lib_name))
            exit()

        bf = r2pipe.open(file_lib, ["-2"])
        bf.cmd("aaaaaa")

        # is that better?
        bf.cmd("aab")
        bf.cmd("aav")

        imported_fun = {}

        # get exported symbol (!= imp.*)
        for s in bf.cmdj("isj"):

            typ = s["type"]   # u'type': u'FUNC'
            bind = s["bind"]  # u'bind': u'GLOBAL',
            is_imported = s["is_imported"] # False ?
            vaddr = s["vaddr"]
            name = s["name"]

            if typ == "FUNC" and bind == "GLOBAL" and is_imported:
                imported_fun[vaddr] = name

        return imported_fun


    @staticmethod
    def is_sgxsdk(task, elfs_map):
        
        has_libsgx_urts = any( [ "libsgx_urts.so" in k for k in elfs_map.keys() ] )

        imp_fcts = ExternalAnalyzerFINGERPRINT._get_imported_functions(elfs_map)

        has_sgxecall = any( [ "sgx_ecall" in x for x in imp_fcts.itervalues() ] )

        return has_libsgx_urts and has_sgxecall


    @staticmethod
    def is_openenclave(task, elfs_map):
        
        has_openenclave_str = any(["openenclave" in s for s in ExternalAnalyzerFINGERPRINT._get_string(elfs_map)])

        return has_openenclave_str

    @staticmethod
    def is_asylo(task, elfs_map):
        
        has_asylo_str = any(["asylo" in s for s in ExternalAnalyzerFINGERPRINT._get_string(elfs_map)])

        return has_asylo_str

    @staticmethod
    def is_graphene(task_t, elfs_map):
        strs = ExternalAnalyzerFINGERPRINT._get_string(elfs_map)
        has_graphene_str = any(["graphene" in s.lower() for s in strs])
        has_devgsgx_str = any(["/dev/gsgx" in s.lower() for s in strs])

        has_mainelf_pal = False
        for k, v in elfs_map.iteritems():
            if v["main"]:
                has_mainelf_pal = "pal-" in k.lower()
                break

        return has_devgsgx_str and has_graphene_str and has_mainelf_pal

    @staticmethod
    def is_sgxlkl(task_t, elfs_map):

        is_openenclave = ExternalAnalyzerFINGERPRINT.is_openenclave(task_t, elfs_map)

        has_mainelf_sgxlklrun = False
        for k, v in elfs_map.iteritems():
            if v["main"]:
                has_mainelf_sgxlklrun = "sgx-lkl-run" in k.lower()
                break
        
        return has_mainelf_sgxlklrun and is_openenclave

    @staticmethod
    def is_rustsdk(task_t, elfs_map):
        
        has_libsgx_urts = any( [ "libsgx_urts.so" in k for k in elfs_map.keys() ] )

        imp_fcts = ExternalAnalyzerFINGERPRINT._get_imported_functions(elfs_map)

        has_sgxecall = any( [ "sgx_ecall" in x for x in imp_fcts.itervalues() ] )

        return has_libsgx_urts and not has_sgxecall