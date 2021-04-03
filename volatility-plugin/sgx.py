"""
@author:       Andrea Oliveri
@license:      GNU General Public License 2.0
@contact:      andrea.oliveri@eurecom.fr
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.iomem as linux_iomem
import volatility.plugins.linux.dmesg as linux_dmesg
import volatility.plugins.linux.lsmod as linux_lsmod
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.psxview as linux_psxview
from volatility.plugins.addrspaces.lime import LimeAddressSpace

# import volatility.plugins.linux.process_stack as linux_process_stack
# import volatility.plugins.linux.process_info as linux_process_info

from volatility.plugins.overlays.linux.linux import task_struct

from volatility.renderers.html import HTMLRenderer, JSONRenderer
from volatility.renderers.text import TextRenderer, FormatCellRenderer, GrepTextRenderer
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

# contains a static analyzer for interface analysis
from external_analyzer import ExternalAnalyzerSGXSDK, ExternalAnalyzerOE, ExternalAnalyzerASYLO, ExternalAnalyzerGRAPHENE, ExternalAnalyzerSGXLKL, ExternalAnalyzerRUSTSDK, ExternalAnalyzerFINGERPRINT

import json, tempfile, string
from struct import *

class EPCBank:
    def __init__(self, name, start, end):
        self.name = name
        self.start = start
        self.end = end

    def __repr__(self):
        return "{}\t{} - {}".format(self.name, hex(self.start), hex(self.end))

    def __hash__(self):
        return hash((self.start, self.end))

    def __eq__(self, other):
        return self.start == other.start and self.end == other.end

class SGXEnclave:
    def __init__(self, parent_task, estruct, driver, mode, framework, main_elf):

        self.parent_task = parent_task
        self.estruct = estruct
        self.driver = driver
        self.einfo = {}
        self.pinfo = {}

        self.framework = framework

        self.main_elf = main_elf

        self.pinfo["pid"] = self.parent_task.pid
        self.pinfo["name"] = self.parent_task.comm
        self.enclave_type = None

        # Raw enclaves
        if driver is None:
            self.is_raw = True
            return
        self.is_raw = False

        if not self._check_enclave_validity():
            raise ValueError

        self.einfo["base"] = self.estruct.base
        self.einfo["size"] = self.estruct.m("size")
        self.einfo["flags"] = self.decode_flags()
        self.einfo["xfrm"] = self.estruct.xfrm if driver == "isgx" else -1
        self.einfo["ssa_size"] = self.estruct.ssaframesize

        self.mode = mode

    def performs_long_operations(self):
        # NOTE for future developres, I moved the enclave analysis here because I noticed that the plugin creates multiple copies of the same object SGXEnclave
        # referring to the same actual enclave. Therefore, moving the analysis here saves time since this information is only required in the generation() function
        if self.mode == 'M' or self.mode == 'B':
            self._extract_memory_layout()
        else:
            self.einfo["type"] = None
            self.einfo["mmap"] = None
            self.einfo["tcss"] = None

        if self.mode == 'I' or self.mode == 'B':
            print("Look for interface information... very slow!")
            self._extract_interface_info()
        else:
            self.einfo["framework"] = None
            self.einfo["ecreate"] = None
            self.einfo["interface"] = []
            # self.einfo["ecalls"] = None
            # self.einfo["ocalls"] = None

    def _extract_interface_info(self):

        elfs_map = self._dump_elfs()

        # for k, v in elfs_map.iteritems():
        #     print("{} -> {} [{}]".format(k, v["file_path"], v["main"]))
        # exit()

        # print(elfs_map)

        task_t = self.parent_task

        # min_enclave = self.estruct.base
        # max_enclave = self.estruct.m("size")

        framework_strategy = None
        if self.framework is None:
            framework_strategy = self._infer_framework(task_t, elfs_map)
        else:
            framework_strategy = self.framework

        if framework_strategy == "sgxsdk":
        #     ecreate, ecalls, ocalls = self._infer_interfaces_sgxsdk(task_t, elfs_map)
            ecreate, interface = self._infer_interfaces_sgxsdk(task_t, elfs_map)
        elif framework_strategy == "openenclave":
        #     ecreate, ecalls, ocalls = self._infer_interfaces_openenclave(task_t, elfs_map)
            ecreate, interface = self._infer_interfaces_openenclave(task_t, elfs_map)
        elif framework_strategy == "asylo":
        #     ecreate, ecalls, ocalls = self._infer_interfaces_asylo(task_t, elfs_map)
            ecreate, interface = self._infer_interfaces_asylo(task_t, elfs_map)
        elif framework_strategy == "graphene":
        #     ecreate, ecalls, ocalls = self._infer_interfaces_graphene(task_t, elfs_map)
            ecreate, interface = self._infer_interfaces_graphene(task_t, elfs_map)
        elif framework_strategy == "sgxlkl":
        #     ecreate, ecalls, ocalls = self._infer_interfaces_sgxlkl(task_t, elfs_map)
            ecreate, interface = self._infer_interfaces_sgxlkl(task_t, elfs_map)
        elif framework_strategy == "rustsdk":
        #     ecreate, ecalls, ocalls = self._infer_interfaces_rustsdk(task_t, elfs_map)
            ecreate, interface = self._infer_interfaces_rustsdk(task_t, elfs_map)
        else:
            ecreate, interface = [], []

        self.einfo["framework"] = framework_strategy
        self.einfo["ecreate"] = ecreate
        # self.einfo["ecalls"] = ecalls
        # self.einfo["ocalls"] = ocalls
        self.einfo["interface"] = interface

    def _get_line(self, probe, task):
        # TODO, this method sucks! I didn't find another way to extract the page permission from a virtual address
        for vma in task.get_proc_maps():
            vm_start = int(vma.vm_start)
            vm_end = int(vma.vm_end)
            vm_flags = str(vma.vm_flags)

            (fname, major, minor, ino, pgoff) = vma.info(task)

            if probe >= vm_start and probe <= vm_end:
                return [vm_flags, fname, (vm_start, vm_end)]

        return None

    def _find_ecall_token_table(self, elfs_map, task):
        valid_ascii = string.ascii_letters + string.digits + '_'

        possible_ecalls = list()
        possible_ecalls_size = list()
        possible_ecall_table_content = {}

        elf_name = None
        elf_start = None
        elf_end = None

        for k, v in elfs_map.iteritems():
            if v["main"]:
                elf_name = k #v["file_path"]
                elf_start = v["vm_start"]
                elf_end = v["vm_end"]
                break

        if not elf_name:
            print("Cannot find main ELF")
            exit()

        # to read things
        proc_as = task.get_process_address_space()

        for vma in task.get_proc_maps():
            vm_start = int(vma.vm_start)
            vm_end = int(vma.vm_end)
            vm_flags = str(vma.vm_flags)

            (fname, major, minor, ino, pgoff) = vma.info(task)

            # exclude pages not belonging to main ELF
            if elf_name not in fname:
                continue

            # exclude writable pages
            if vma.vm_flags.is_writable():
                continue

            # exclude exec pages
            if vma.vm_flags.is_executable():
                continue

            # print("seek 0x{:x} 0x{:x} {} {}".format(vm_start, vm_end, vm_flags, fname))

            # from IPython import embed; embed(); exit()

            offset = vm_start
            max_offset = vm_end

            offset_begin_table = 0
            n_ecall = 0

            b = proc_as.zread(offset, 8)
            offset += 8

            while offset <= max_offset:

                maybe_add_str = unpack("<Q", b)[0]

                # print("read 0x{:02x} @ 0x{:02x}".format(maybe_add_str, offset))

                # if maybe_add_str == 0x556e8bcc0450:
                #     from IPython import embed; embed(); exit()

                # idx_line = great_idx.from_vaddr_to_line(maybe_add_str)
                idx_line = self._get_line(maybe_add_str, task)
                # if maybe_add_str != 0 and idx_line and idx_line[0] in ["r--", "r-x"] and idx_line[1] == elf_name:
                if maybe_add_str != 0 and idx_line and idx_line[0] in ["r--", "r-x"] and  elf_name in idx_line[1]:
                    # print("-> 0x{:x} points to const page ".format(maybe_add_str))
                    # print("-> 0x{:x} 0x{:x} {} {}".format(idx_line[2][0], idx_line[2][1], idx_line[0], idx_line[1]))
                    # print("-")

                    # from IPython import embed; embed(); exit()

                    # offset_add_str = great_idx.from_vaddr_to_offest(maybe_add_str)
                    offset_add_str = maybe_add_str

                    # file.seek(offset_add_str)
                    # bb = file.read(1)
                    bb = proc_as.zread(offset_add_str, 1)

                    offset_add_str += 1
                    is_string = False
                    while True:
                        # print(bb)
                        # NULL-terminator
                        if bb == '\x00':
                            # print("end str")
                            is_string = True
                            break
                        if bb not in valid_ascii:
                            is_string = False
                            break

                        # print(bb)

                        # bb = file.read(1)
                        bb = proc_as.zread(offset_add_str, 1)
                        offset_add_str += 1

                    # print(bb)
                    # file.seek(offset)

                    if is_string:
                        # print("a string @ 0x{:02x} - 0x{:02x}".format(maybe_add_str, (maybe_add_str-elf_start)))
                        if not offset_begin_table:
                            # print("a new table")
                            offset_begin_table = offset - 8
                        n_ecall += 1
                    else:
                        # print("not a string 2")
                        if offset_begin_table:
                            # print("that's a table 2!")
                            # ecall_table = great_idx.from_offset_to_vaddr(offset_begin_table)
                            ecall_table = offset_begin_table
                            possible_ecalls += [ecall_table]
                            possible_ecalls_size += [n_ecall]
                            # print("[OK!] A possible ecall_table @ 0x{:02x} with {} items".format(ecall_table,n_ecall))
                        offset_begin_table = 0
                        n_ecall = 0
                else:
                    # print("not a string")
                    if offset_begin_table:
                        # print("that's a table 1!")
                        # ecall_table = great_idx.from_offset_to_vaddr(offset_begin_table)
                        ecall_table = offset_begin_table
                        possible_ecalls += [ecall_table]
                        possible_ecalls_size += [n_ecall]
                        # print("[OK!] A possible ecall_table @ 0x{:02x} with {} items".format(ecall_table, n_ecall))
                    offset_begin_table = 0
                    n_ecall = 0

                # b = file.read(8)
                # offset += 8
                b = proc_as.zread(offset, 8)
                offset += 8

        for ec, ec_size in zip(possible_ecalls, possible_ecalls_size):

            possible_ecall_table_content[ec] = []

            for i in range(ec_size):
                ec_add_byte = proc_as.zread(ec + i*8, 8)
                ec_add = unpack("<Q", ec_add_byte)[0]
                possible_ecall_table_content[ec] += [ec_add]


        return possible_ecall_table_content

    def _find_possible_ocall_table2(self, elfs_map, task):

        possible_ocalls = list()
        possible_ocalls_size = list()

        # to read things
        proc_as = task.get_process_address_space()

        elf_name = None
        elf_start = None
        elf_end = None

        for k, v in elfs_map.iteritems():
            if v["main"]:
                elf_name = k #v["file_path"]
                elf_start = v["vm_start"]
                elf_end = v["vm_end"]
                break

        if not elf_name:
            print("Cannot find main ELF")
            exit()

        # print("ELF {}".format(elf_name))

        for vma in task.get_proc_maps():
            vm_start = int(vma.vm_start)
            vm_end = int(vma.vm_end)
            vm_flags = str(vma.vm_flags)

            (fname, major, minor, ino, pgoff) = vma.info(task)

            # exclude pages not belonging to main ELF
            if elf_name not in fname:
                continue

            # # exclude writable pages
            # if vma.vm_flags.is_writable():
            #     continue

            # exclude exec pages
            if vma.vm_flags.is_executable():
                continue

            # print("seek: {} 0x{:x} 0x{:x} {}".format(fname, vm_start, vm_end, vm_flags))

            offset = vm_start
            max_offset = vm_end

            b = proc_as.zread(offset, 8)
            offset += 8

            # print("[INFO] offset: 0x{:x}".format(offset))
            # print("[INFO] max_offset: 0x{:x}".format(max_offset))

            ocall_addr = 0
            n_ocall = 0

            while offset <= max_offset:
                # print("[INFO] offset: 0x{:x}".format(offset))
                # maybe_add_fun = int.from_bytes(b, byteorder='little', signed=False)
                maybe_add_fun = unpack("<Q", b)[0]

                # NULL value that ends the table
                if maybe_add_fun == 0:
                    if ocall_addr:
                        # ocall_addr = great_idx.from_offset_to_vaddr(offset_begin_table)
                        # print("[OK!] A possible ocall_table @ 0x{:02x} with {} ocall".format(ocall_addr, n_ocall))
                        # print(x_line["raw"])
                        possible_ocalls += [ocall_addr]
                        possible_ocalls_size += [n_ocall]
                        ocall_addr = 0
                        n_ocall = 0
                # else, check the pointer goes to an exec page of the same file
                else:
                    idx_line = self._get_line(maybe_add_fun, task)
                    # if idx_line and "x" in idx_line[0] and "w" not in idx_line[0] and "r" in idx_line[0] and idx_line[1] == elf_name:
                    if idx_line and idx_line[0] == "r-x" and elf_name in idx_line[1]:
                        if not ocall_addr:
                            ocall_addr = offset - 8
                        n_ocall += 1
                    else:
                        if n_ocall > 0:
                            # print("[OK!] A possible ocall_table @ 0x{:02x} with {} ocall".format(ocall_addr, n_ocall))
                            possible_ocalls += [ocall_addr]
                            possible_ocalls_size += [n_ocall]
                        ocall_addr = 0
                        n_ocall = 0

                b = proc_as.zread(offset, 8)
                offset += 8

        return (possible_ocalls, possible_ocalls_size)

    def _find_possible_ocall_table(self, elfs_map, task):

        possible_ocalls = []
        # to read things
        proc_as = task.get_process_address_space()

        elf_name = None
        elf_start = None
        elf_end = None

        for k, v in elfs_map.iteritems():
            if v["main"]:
                elf_name = k #v["file_path"]
                elf_start = v["vm_start"]
                elf_end = v["vm_end"]
                break

        if not elf_name:
            print("Cannot find main ELF")
            exit()

        # from IPython import embed; embed()


        for vma in task.get_proc_maps():
            vm_start = int(vma.vm_start)
            vm_end = int(vma.vm_end)
            vm_flags = str(vma.vm_flags)

            (fname, major, minor, ino, pgoff) = vma.info(task)

            # print("probe: {} 0x{:x} 0x{:x} {}".format(fname, vm_start, vm_end, vm_flags))

            # exclude pages not belonging to main ELF
            if elf_name not in fname:
                continue

            # exclude exec pages
            if vma.vm_flags.is_writable():
                continue

            # print("seek: {} 0x{:x} 0x{:x} {}".format(fname, vm_start, vm_end, vm_flags))

            offset = vm_start
            max_offset = vm_end

            b = proc_as.zread(offset, 8)
            offset += 8

            while offset <= max_offset:

                # print("offset 0x{:x}".format(offset))
                x = unpack("<Q", b)[0]

                # if offset == 0x7fb1a24cf980:
                #     from IPython import embed; embed()

                # print("offset 0x{:x}".format(offset))

                if x > 0 and x < 1000:
                    n_add_exec = 0
                    for i in range(x):
                        maybe_add_fun_bytes = proc_as.zread(offset + i*8, 8)
                        maybe_add_fun = unpack("<Q", maybe_add_fun_bytes)[0]
                        # idx_line = self._get_line(maybe_add_fun, task)
                        idx_line = self._get_line(maybe_add_fun, task)
                        if idx_line:
                            if idx_line[0] == "r-x" and elf_name in idx_line[1]:
                                # print("[OK!] 0x{:02x}".format(maybe_add_fun))
                                n_add_exec += 1
                            else:
                                # print("[STOP]")
                                break
                        else:
                            # print("[STOP]")
                            break

                    if n_add_exec == x:
                        ocall_addr = offset - 8
                        # print("[OK!] A possible ocall_table @ 0x{:02x} (0x{:02x}) with {} ocall".format(ocall_addr, ocall_addr-elf_start, x))
                        possible_ocalls += [ocall_addr]

                b =  proc_as.zread(offset, 8)
                offset += 8

        # print("[INFO] all possible ocalls found:")
        # print(" ".join(["0x{:02x}".format(o) for o in possible_ocalls]))
        return possible_ocalls

    def _infer_interfaces_sgxsdk(self, task, elfs_map):

        interface_map = []

        possible_ocalls = self._find_possible_ocall_table(elfs_map, task)

        try:
            # ecreate, ecalls, ocall_tables = ExternalAnalyzerSGXSDK.extract_interface(elfs_map, possible_ocalls)
            ecreate, pair_ecall_ocall_table = ExternalAnalyzerSGXSDK.extract_interface(elfs_map, possible_ocalls)
        except Exception, e:
            print("exception here")
            from IPython import embed; embed(); exit()

        # print(pair_ecall_ocall_table)
        # exit()

        for ecalls, ocall_table in pair_ecall_ocall_table:

            if ecalls:

                ocalls = set()

                if ocall_table != 0x0:

                    # to read things
                    proc_as = task.get_process_address_space()

                    num_ocall_bytes = proc_as.zread(ocall_table, 8)
                    num_ocall = unpack("<Q", num_ocall_bytes)[0]

                    for i in range(num_ocall):
                        ocall_add_bytes = proc_as.zread(ocall_table + (i+1)*8, 8)
                        ocall_add = unpack("<Q", ocall_add_bytes)[0]
                        ocalls.add(ocall_add)

                interface_map.append({"ebase": None, "ecall": list(ecalls), "ocall": list(ocalls)})

        return ecreate, interface_map

    def _infer_interfaces_rustsdk(self, task, elfs_map):

        pltjmp = ExternalAnalyzerRUSTSDK.extract_pltjmp(elfs_map)
        # print(pltjmp)

        exported_fun = ExternalAnalyzerRUSTSDK.extract_exported_fun(elfs_map, "libsgx_urts.so")
        # print(exported_fun)

        # get libsgx_urts.so base address
        libsgx_urts_ba = None
        for k, v in elfs_map.iteritems():
            if "libsgx_urts.so" in k:
                libsgx_urts_ba = v["vm_start"]
                break

        if libsgx_urts_ba is None:
            print("[ERROR] libsgx_urts.so not found!")
            exit()

        # to read things
        proc_as = task.get_process_address_space()

        plt_decoded = {}

        for k, v in pltjmp.iteritems():
            ptr_bytes = proc_as.zread(v, 8)
            ptr_add = unpack("<Q", ptr_bytes)[0]
            ptr_add_rel = ptr_add - libsgx_urts_ba

            if ptr_add_rel in exported_fun:
                fun_name = exported_fun[ptr_add_rel]
                plt_decoded[k] = fun_name
            # else:
            #     fun_name = "not in libsgx_urts.so"

            # print("0x{:x} -> 0x{:x} -> 0x{:x} -> 0x{:x} | [{}]".format(k, v, ptr_add, ptr_add_rel, fun_name))

        # print("")
        # for f, n in plt_decoded.iteritems():
        #     print("0x{:x} => {}".format(f, n))
        # exit()

        possible_ocall_table = self._find_possible_ocall_table(elfs_map, task)

        try:
            pair_ecall_ocall_table = ExternalAnalyzerRUSTSDK.extract_interface(elfs_map, possible_ocall_table, plt_decoded)
        except Exception, e:
            print("an exception here")
            from IPython import embed; embed(); exit()

        interface_map = []

        for ecalls, ocall_table in pair_ecall_ocall_table:

            if ecalls:

                ocalls = set()

                if ocall_table != 0x0:

                    # to read things
                    proc_as = task.get_process_address_space()

                    num_ocall_bytes = proc_as.zread(ocall_table, 8)
                    num_ocall = unpack("<Q", num_ocall_bytes)[0]

                    for i in range(num_ocall):
                        ocall_add_bytes = proc_as.zread(ocall_table + (i+1)*8, 8)
                        ocall_add = unpack("<Q", ocall_add_bytes)[0]
                        ocalls.add(ocall_add)

                interface_map.append({"ebase": None, "ecall": list(ecalls), "ocall": list(ocalls)})

        return [], interface_map

    def _infer_interfaces_sgxlkl(self, task, elfs_map):

        (possible_ocall_table, possible_ocall_table_size) = self._find_possible_ocall_table2(elfs_map, task)
        # print("Number of possible ocall_table found: {}".format(len(possible_ocall_table)))

        ecreate, ecalls, ocall_tables, ocall_table_size = ExternalAnalyzerSGXLKL.extract_interface(elfs_map, possible_ocall_table, possible_ocall_table_size)

        ocalls = set()
        # to read things
        proc_as = task.get_process_address_space()
        for ot, ot_size in zip(ocall_tables, ocall_table_size):

            for i in range(ot_size):
                ocall_add_bytes = proc_as.zread(ot + i*8, 8)
                ocall_add = unpack("<Q", ocall_add_bytes)[0]
                ocalls.add(ocall_add)

        interface_map = []
        interface_map.append({"ebase": None, "ecall": list(ecalls), "ocall": list(ocalls)})

        return ecreate, interface_map

    def _infer_interfaces_graphene(self, task, elfs_map):

        # print(elfs_map)

        (possible_ocall_table, possible_ocall_table_size) = self._find_possible_ocall_table2(elfs_map, task)
        # print("Number of possible ocall_table found: {}".format(len(possible_ocall_table)))

        ecalls, ocall_tables, ocall_table_size = ExternalAnalyzerGRAPHENE.extract_interface(elfs_map, possible_ocall_table, possible_ocall_table_size)

        ocalls = set()
        # to read things
        proc_as = task.get_process_address_space()
        for ot, ot_size in zip(ocall_tables, ocall_table_size):

            for i in range(ot_size):
                ocall_add_bytes = proc_as.zread(ot + i*8, 8)
                ocall_add = unpack("<Q", ocall_add_bytes)[0]
                ocalls.add(ocall_add)

        interface_map = []
        interface_map.append({"ebase": None, "ecall": list(ecalls), "ocall": list(ocalls)})

        return [], interface_map

    def _infer_interfaces_asylo(self, task, elfs_map):

        ecalls = ExternalAnalyzerASYLO.extract_interface(elfs_map)

        interface_map = []
        interface_map.append({"ebase": None, "ecall": list(ecalls), "ocall": []})

        return [], interface_map

    def _infer_interfaces_openenclave(self, task, elfs_map):

        ecreate = []
        # ecalls = []
        # ocalls = []
        interface_map = []

        (possible_ocall_table, possible_ocall_table_size) = self._find_possible_ocall_table2(elfs_map, task)
        # print("Number of possible ocall_table found: {}".format(len(possible_ocall_table)))

        possible_ecall_table_content = self._find_ecall_token_table(elfs_map, task)
        # print("Number of possible ecall_token_table found: {}".format(len(possible_ecall_table_content)))

        # ecreate, ecalls, ocall_tables, ocall_table_size = ExternalAnalyzerOE.extract_interface(elfs_map, possible_ocall_table, possible_ocall_table_size, possible_ecall_table_content)
        ecreate, pair_ecall_ocalltable_ocalltablesize = ExternalAnalyzerOE.extract_interface(elfs_map, possible_ocall_table, possible_ocall_table_size, possible_ecall_table_content)

        for ecalls, ocall_table, ocall_table_size  in pair_ecall_ocalltable_ocalltablesize:

            if ecalls:

                ocalls = set()

                if ocall_table != 0x0:

                    # to read things
                    proc_as = task.get_process_address_space()
                    for i in range(ocall_table_size):
                        ocall_add_bytes = proc_as.zread(ocall_table + i*8, 8)
                        ocall_add = unpack("<Q", ocall_add_bytes)[0]
                        ocalls.add(ocall_add)

                interface_map.append({"ebase": None, "ecall": list(ecalls), "ocall": list(ocalls)})

        return ecreate, interface_map
        # return ecreate, ecalls, ocalls

    def _infer_framework(self, task_t, elfs_map):
        # The heuristic is a combination of distinguishability among single indicators and hierarchy of SGX framework

        heuristics_results = {}

        heuristics_results["sgxsdk"] = ExternalAnalyzerFINGERPRINT.is_sgxsdk(task_t, elfs_map)
        heuristics_results["openenclave"] = ExternalAnalyzerFINGERPRINT.is_openenclave(task_t, elfs_map)
        heuristics_results["asylo"] = ExternalAnalyzerFINGERPRINT.is_asylo(task_t, elfs_map)
        heuristics_results["graphene"] = ExternalAnalyzerFINGERPRINT.is_graphene(task_t, elfs_map)
        heuristics_results["sgxlkl"] = ExternalAnalyzerFINGERPRINT.is_sgxlkl(task_t, elfs_map)
        heuristics_results["rustsdk"] = ExternalAnalyzerFINGERPRINT.is_rustsdk(task_t, elfs_map)

        # no one returned true, I can't decide the framework
        if sum([v for v in heuristics_results.itervalues()]) == 0:
            return "unknown"

        # only one got true!
        if sum([v for v in heuristics_results.itervalues()]) == 1:
            # I return the only true
            return [k for k, v in heuristics_results.iteritems() if v][0]

        # special case sgx-lkl and openenclave
        if sum([v for v in heuristics_results.itervalues()]) == 2 and heuristics_results["openenclave"] and heuristics_results["sgxlkl"]:
            return "sgxlkl"

        return "unknown"

    def _dump_elfs(self):

        tmpfolder = tempfile.mkdtemp()

        elfs_map = {}

        task = self.parent_task

        prv_main_elf = self.main_elf if self.main_elf != 0 else  task.mm.start_code

        for elf, elf_start, elf_end, soname, needed in task.elfs():
            file_path = linux_common.write_elf_file(tmpfolder, task, elf.v())
            elfs_map[soname] = {}
            elfs_map[soname]["file_path"] = file_path
            elfs_map[soname]["vm_start"] = elf_start
            elfs_map[soname]["vm_end"] = elf_end
            elfs_map[soname]["main"] = prv_main_elf == elf_start

        return elfs_map

    def _check_enclave_validity(self):
        # Check if all the reference in sgx_encl struct are valid

        if not self.estruct.backing.is_valid() or \
           not self.estruct.va_pages.prev.is_valid():
           return False

        if self.driver == "isgx":
            if  not self.estruct.mm.is_valid() or \
                not self.estruct.pcmd.is_valid() or \
                not self.estruct.load_list.next.is_valid() or \
                not self.estruct.load_list.prev.is_valid() or \
                not self.estruct.add_page_reqs.next.is_valid() or \
                not self.estruct.add_page_reqs.prev.is_valid() or \
                not self.estruct.tgid_ctx.is_valid() or \
                not self.estruct.encl_list.next.is_valid() or \
                not self.estruct.encl_list.prev.is_valid():
                return False
        else:
            if  not self.estruct.mm_list.next.is_valid() or \
                not self.estruct.mm_list.prev.is_valid():
                return False

        return True

    def decode_flags(self):
        if self.driver == "isgx":
            flags = {
                1: "INITIALIZED",
                2: "DEBUG",
                4: "SECS_EVICTED",
                8: "SUSPEND",
                16: "DEAD"
            }
        else:
            flags = {
                1:  "CREATED",
                2:  "INITIALIZED",
                4:  "DEBUG",
                8:  "DEAD",
                16: "BUSY"
            }

        attributes = {
            1:   "INITIALIZED",
            2:   "DEBUG",
            4:   "MODE_64BIT",
            16:  "PROVISION_KEY",
            32:  "EINIT_TOKEN_KEY",
            128: "KSS"
        }

        if self.driver == "dcap":
            flags_s = self.estruct.flags.counter
            attributes_s = self.estruct.secs_attributes
        else:
            flags_s = self.estruct.flags
            attributes_s = self.estruct.attributes

        flags_l = set()
        for pos, flag in flags.items():
            if flags_s & pos:
                flags_l.add(flag)

        for pos, attr in attributes.items():
            if attributes_s & pos:
                flags_l.add(attr)

        flags_l = list(flags_l)
        flags_l.sort()
        return flags_l

    def _extract_memory_layout(self):
        # Extract memory layout from a SGX enclave loaded by Intel drivers
            min_eaddr = int(self.einfo["base"])
            max_eaddr = min_eaddr + int(self.einfo["size"])
            enclave_mmaps = []
            for vma in self.parent_task.get_proc_maps():
                vm_start = int(vma.vm_start)
                vm_end = int(vma.vm_end)
                vm_flags = str(vma.vm_flags)

                if vm_start >= min_eaddr and vm_end <= max_eaddr:
                    enclave_mmaps.append([vm_start, vm_end, vm_flags, None])

            # Identify additional information of the enclave
            is_container, emmaps_tags_container, tcss_container = self._try_tag_container(enclave_mmaps)
            is_elrange, emmaps_tags_elrange, tcss_elrange = self._try_tag_elrange(enclave_mmaps)

            if is_container:
                self.einfo["type"] = "CONTAINER"
                self.einfo["mmap"] = emmaps_tags_container
                self.einfo["tcss"] = tcss_container
            elif is_elrange:
                self.einfo["type"] = "ELRANGE"
                self.einfo["mmap"] = emmaps_tags_elrange
                self.einfo["tcss"] = tcss_elrange
            else:
                self.einfo["type"] = "UNKNOWN"
                self.einfo["mmap"] = enclave_mmaps
                self.einfo["tcss"] = []

    def _try_tag_container(self, enclave_mmaps):
        # If the enclaves is based on a container the mmaps has RWX flags
        is_container = False
        enclave_mmaps_tags = []

        for start, end, flags, n_tag in enclave_mmaps:
            tag = None
            if flags == "rwx":
                is_container = True
                tag = 'CONTAINER'
            enclave_mmaps_tags.append([start, end, flags, tag])

        return is_container, enclave_mmaps_tags, []

    def _try_tag_elrange(self, enclave_mmaps):

        is_elrange = False
        enclave_mmaps_tags = []

        is_firstthread = True
        guard_size = 0
        stack_size = 0
        tcsssas_size = 0
        tls_size = 0
        tcss = []

        phase = "PADDING" # PADDING THREAD
        t_phase_pr = None
        t_phase = "TLS" # TLS TCSSSA STACK GUARDT

        # last valid thread page
        last_thread = len(enclave_mmaps)

        try:
            for i, (start, end, flags, n_tag) in reversed(list(enumerate(enclave_mmaps[:]))):

                raw = "(0x%x, 0x%x, %s)" % (start, end, flags)
                vadd_start = start
                vadd_end = end

                b_size = vadd_end - vadd_start + 1

                is_read = "r" in flags
                is_write = "w" in flags
                is_exec = "x" in flags

                if phase == "PADDING":
                    # ---
                    if (is_read, is_write, is_exec) == (False, False, False):
                        enclave_mmaps_tags.append([start, end, flags, None])
                        phase = "THREAD"
                    else:
                        raise Exception("Page [%s] does not fit the template" % raw)

                elif phase == "THREAD":
                    if t_phase == "TLS":
                        if (is_read, is_write, is_exec) == (True, True, False):

                            is_tlsok = False
                            if is_firstthread:
                                tls_size = b_size
                                is_tlsok = True
                            elif b_size == tls_size:
                                is_tlsok = True
                            else:
                                raise Exception("TLS page [%s] does not fit the template" % raw)

                            if is_tlsok:
                                enclave_mmaps_tags.append([start, end, flags, t_phase])
                                t_phase_pr = t_phase
                                t_phase = "GUARDT"

                        else:
                            raise Exception("Page [%s] does not fit the template" % raw)

                    elif t_phase == "TCSSSA":
                        if (is_read, is_write, is_exec) == (True, True, False):

                            is_tcsok = False
                            if is_firstthread:
                                tcsssas_size = b_size
                                is_tcsok = True
                            elif b_size == tcsssas_size:
                                is_tcsok = True
                            else:
                                raise Exception("TCS/SSA page [%s] does not fit the template" % raw)

                            if is_tcsok:
                                enclave_mmaps_tags.append([start, end, flags, t_phase])
                                tcss += [vadd_start]
                                t_phase_pr = t_phase
                                t_phase = "GUARDT"

                        else:
                            raise Exception("Page [%s] does not fit the template" % raw)

                    elif t_phase == "STACK":
                        if (is_read, is_write, is_exec) == (True, True, False):

                            is_stackok = False
                            if is_firstthread:
                                stack_size = b_size
                                is_stackok = True
                            elif b_size == stack_size:
                                is_stackok = True
                            else:
                                raise Exception("STACK page [%s] does not fit the template" % raw)

                            if is_stackok:
                                enclave_mmaps_tags.append([start, end, flags, t_phase])
                                t_phase_pr = t_phase
                                t_phase = "GUARDT"
                                is_firstthread = False

                        else:
                            raise Exception("Page [%s] does not fit the template" % raw)

                    elif t_phase == "GUARDT":
                        if (is_read, is_write, is_exec) == (False, False, False):

                            is_guardtok = False
                            if is_firstthread:
                                guard_size = b_size
                                is_guardtok = True
                            elif b_size == guard_size:
                                is_guardtok = True
                            else:
                                raise Exception("GUARD THREAD page [%s] does not fit the template" % raw)

                            if is_guardtok:
                                enclave_mmaps_tags.append([start, end, flags, None])
                                last_thread = min(i, last_thread)

                                if t_phase_pr == "TLS":
                                    t_phase_pr = t_phase
                                    t_phase = "TCSSSA"
                                elif t_phase_pr == "TCSSSA":
                                    t_phase_pr = t_phase
                                    t_phase = "STACK"
                                elif t_phase_pr == "STACK":
                                    t_phase_pr = t_phase
                                    t_phase = "TLS"

                        else:
                            raise Exception("Page [%s] does not fit the template" % raw)
                    else:
                        raise Exception("Page [%s] does not fit the template" % raw)

        except Exception as e:
            pass


        enclave_mmaps_tags_2 = []

        for i, (start, end, flags, n_tag) in enumerate(enclave_mmaps[:]):
            # select only lines belonging to current enclave
            if  i >= last_thread:
                continue

            raw = "(0x%x, 0x%x, %s)" % (start, end, flags)
            vadd_start = start
            vadd_end = end

            b_size = vadd_end - vadd_start

            is_read = "r" in flags
            is_write = "w" in flags
            is_exec = "x" in flags

            if i == 0 and (is_read, is_write, is_exec) == (True, False, False):
                enclave_mmaps_tags_2.append([start, end, flags, "HEADER"])
            else:
                # r--
                if (is_read, is_write, is_exec) == (True, False, False):
                    enclave_mmaps_tags_2.append([start, end, flags, "CONSTANT"])
                # rw-
                elif (is_read, is_write, is_exec) == (True, True, False):
                    enclave_mmaps_tags_2.append([start, end, flags, "GLOBAL"])
                # r-x
                elif (is_read, is_write, is_exec) == (True, False, True):
                    enclave_mmaps_tags_2.append([start, end, flags, "CODE"])
                # ---
                elif (is_read, is_write, is_exec) == (False, False, False):
                    enclave_mmaps_tags_2.append([start, end, flags, None])
                # rwx
                elif (is_read, is_write, is_exec) == (True, True, True):
                    return False, [], []

        enclave_mmaps_tags.reverse()
        enclave_mmaps_tags_2.extend(enclave_mmaps_tags)

        return True, enclave_mmaps_tags_2, tcss

    def __hash__(self):
        return(hash((self.parent_task.v(), self.estruct.v(), self.driver)))

    def __eq__(self, other):
        return self.parent_task == other.parent_task and \
               self.estruct == other.estruct and \
               self.driver == other.driver


class linux_sgx(linux_common.AbstractLinuxCommand):
    """Check support for Intel SGX and find SGX enclaves"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        # Options for search process
        self._config.add_option('FORCE', default = False,
                    help = 'Force to search SGX enclaves which could use custom SGX kernel drivers',
                    action = 'store_true')
        self._config.add_option('HIDDENPROC', short_option = 'x', default = False,
                    help = 'Look for SGX enclaves in hidden processes',
                    action = 'store_true')

        # Options for infomation extraction
        self._config.add_option('PID', short_option = 'p', default = 0,
                    help = 'Operate on this Process ID',
                    action = 'store', type = 'int')
        self._config.add_option('OFFSET', short_option = 'o', default = 0,
                    help = 'Operate on this Offset',
                    action = 'store', type = 'int')
        self._config.add_option('EBASE', default = 0,
                    help = 'Operate on this Enclave',
                    action = 'store', type = 'int')
        self._config.add_option('DUMP-DIR', short_option = 'D', default = None,
                    help = 'Output directory for enclaves ELFs',
                    action = 'store', type = 'str')
        # FOR INTERFACE ANALYSIS
        self._config.add_option('ANALYSIS', short_option = 'a', default = 'B',
                    help = 'Indicate which type of analysis performs over the enclave (I = Interface, M = Memory, B = Both)',
                    action = 'store', type = 'str')
        self.FRAMEWORKS_SUPPORTED = ["sgxsdk", "openenclave" ,"asylo", "graphene", "sgxlkl", "rustsdk"]
        framework_supported_str = "|".join(self.FRAMEWORKS_SUPPORTED)
        self._config.add_option('FRAMEWORK', default = None,
                    help = 'Force the plugin to use a specific framework strategy to infer the enclave interface <{}>'.format(framework_supported_str),
                    action = 'store', type = 'str')
        self._config.add_option('MAINELF', default = 0x0,
                    help = 'Base virtual address of the main ELF object of a given process (using with PID or OFFSET)',
                    action = 'store', type = 'int')

        self.mode = -1

    def calculate(self):
        linux_common.set_plugin_members(self)

        # Check options
        if (self._config.FORCE or self._config.HIDDENPROC) and (self._config.PID or self._config.OFFSET or self._config.DUMP_DIR):
            print("Error! Use only one option group between [FORCE HIDDENPROC] and [PID OFFSET DUMP-DIR]")
            return []

        if self._config.PID and self._config.OFFSET:
            print("Error! Use only one option between [PID OFFSET]")
            return []

        if (not self._config.DUMP_DIR) and (self._config.PID or self._config.OFFSET) and not self._config.EBASE:
            print("Error! Missing EBASE option")
            return []

        if self._config.DUMP_DIR and not (self._config.PID or self._config.OFFSET):
            print("Error! Missing PID or OFFSET for ELF dump mode")
            return []

        if self._config.FRAMEWORK is not None and self._config.FRAMEWORK not in self.FRAMEWORKS_SUPPORTED:
            framework_supported_str = "|".join(self.FRAMEWORKS_SUPPORTED)
            return []

        # Find if LiME addrspace is used
        addr_space = self.addr_space
        while addr_space:
            if isinstance(addr_space, LimeAddressSpace):
                # Look for EPC banks in LiME dumps
                epc_banks_lime = self.find_epc_banks_lime(addr_space)
                break
            addr_space = addr_space.base
        else:
            print("LiME dump format not in use, no info about EPC zones from dump file...")
            epc_banks_lime = set()

        if epc_banks_lime:
            print("EPC banks found through LiME metadata")

        # Look for EPC banks in /proc/iomem
        epc_banks_iomem = self.find_epc_banks_iomem()

        if not self._config.FORCE:
            # Look for Intel SGX kernel module(s) at dump time
            isgx_mod, dcap_mod = self.find_intel_module_loaded()
            if isgx_mod or dcap_mod:
                sgx_mod_prnt = [x[0] for x in isgx_mod + dcap_mod]
                print("Intel SGX driver loaded: {}".format(",".join(sgx_mod_prnt)))
            else:
                print("Intel SGX kernel modules not loaded at dump time, try with --force")
                return []

            # Look for Intel SGX kernel module(s) in dmesg and EPC banks
            dmesg_module_str, epc_banks_dmesg = self.find_intel_module_dmesg()
            if not dmesg_module_str:
                print("Intel SGX kernel modules not loaded at boot time, try with --force")
                return []
            else:
                print("SGX module banner: {}".format(dmesg_module_str))

        else:
            isgx_mod = False
            epc_banks_dmesg = set()

        self.epc_banks = list(epc_banks_iomem.union(epc_banks_dmesg).union(epc_banks_lime))

        if not self.epc_banks:
            print("No EPC zones found... try with --force to find at least the host processes")
            if not self._config.FORCE:
                return []
        else:
            print("SGX EPC banks:\t")
            for epc_bank in self.epc_banks:
                print("\t" + str(epc_bank))

        if (self._config.PID or self._config.OFFSET) and not self._config.DUMP_DIR and not self._config.FORCE:
            self.mode = 0 # Info mode
            return self.show_detailed_info(isgx_mod)
        elif (self._config.PID or self._config.OFFSET) and self._config.DUMP_DIR and not self._config.FORCE:
            self.mode = 1 # ELF dump mode
            return self.dump_enclaves()
        else:
            self.mode = 2 # Find enclave mode
            return self.find_enclaves(isgx_mod)

    def find_epc_banks_lime(self, addr_space):
        """Identify the EPC banks in LiME dumps"""
        epc_banks = set()

        # Find EPC banks
        offset = 0
        header = obj.Object("lime_header", offset = offset, vm = addr_space.base)
        while header.magic.v() == 0x4c694d45:
            if header.reserved == 0x2153475845504321:
                epc_banks.add(EPCBank("", int(header.start), int(header.end)))

            offset = offset + header.end - header.start + 1 + self.profile.get_obj_size("lime_header")
            header = obj.Object("lime_header", offset = offset, vm = addr_space.base)

        return epc_banks

    def find_epc_banks_iomem(self):
        """Find the EPC banks defined by the BIOS/UEFI subsystem"""
        epc_banks = set()
        for iores in linux_iomem.linux_iomem(self._config).calculate():
            _, name, start, end = iores
            name = str(name)
            if "INT0E0C" in name:
                epc_banks.add(EPCBank(name, int(start), int(end)))
        return epc_banks

    def find_intel_module_dmesg(self):
        """Find the Intel SGX driver(s) log output in dmesg"""
        dmesg_module_str = ""
        epc_banks_dmesg = set()

        msg_block = str(list(linux_dmesg.linux_dmesg(self._config).calculate())[0])
        for msg_line in msg_block.split("\n"):

            if "Intel SGX" in msg_line:
                dmesg_module_str = msg_line.split(": ")[-1].strip()

            if "EPC" in msg_line:
                epc_addr, epc_dim = (msg_line.split()[-1]).split("-")
                epc_addr = int(epc_addr, 16)
                epc_dim = int(epc_dim, 16)
                if "bank" in msg_line:
                    epc_dim -= 1
                epc_banks_dmesg.add(EPCBank("", epc_addr, epc_dim))

        return dmesg_module_str, epc_banks_dmesg

    def find_intel_module_loaded(self):
        """Find the Intel SGX driver(s) loaded at dump time"""
        lsmod_module = linux_lsmod.linux_lsmod(self._config)
        isgx_mod = lsmod_module.get_modules(["isgx"])
        dcap_mod = lsmod_module.get_modules(["intel_sgx"])

        return isgx_mod, dcap_mod

    def find_enclaves(self, is_isgx):
        """Find SGX enclaves in dump"""
        proc_iter = self._return_procs()
        if self._config.FORCE:
            return self.find_sgx_enclaves_raw(proc_iter)

        if is_isgx:
            return self.find_sgx_enclaves_intel_drv(proc_iter, "isgx")
        else:
            return self.find_sgx_enclaves_intel_drv(proc_iter, "dcap")

    def _return_procs(self):
        """Return an iterator over the processes"""
        if self._config.HIDDENPROC:
            print("Look for hidden processes... very slow!")
            return [t[1] for t in linux_psxview.linux_psxview(self._config).calculate()]
        else:
            return linux_pslist.linux_pslist(self._config).allprocs()

    def find_sgx_enclaves_raw(self, proc_iter):
        """Scan each single virtual address space looking for addresses translated into EPC pages"""
        enclaves = []
        print("Look for hidden enclaves... very slow! It can produce false positives!")
        for task in proc_iter:

            # Ignore kernel tasks
            if (task.flags & 0x200000):
                continue

            task_addr_sp = task.get_process_address_space()
            try:
                for vma in task.get_proc_maps():

                    # Ignore common mappings and not device related ones
                    if vma.vm_name(task) in ["[vdso]", "[stack]", "[heap]"]:
                        continue
                    flags = vma.flags()
                    if "VM_IO" not in flags and \
                       "VM_PFNMAP" not in flags:
                        continue

                    range_pages = xrange(vma.vm_start, vma.vm_end, 4096)
                    total_pages = len(range_pages)
                    invalid_pages = 0
                    for page_addr in range_pages:

                        phy_pg_addr = task_addr_sp.vtop(page_addr)
                        if not self.epc_banks:
                            if not phy_pg_addr:
                                invalid_pages += 1
                            continue
                        else:
                            if not phy_pg_addr:
                                continue

                        for epc_bank in self.epc_banks:
                            if epc_bank.start <= phy_pg_addr <= epc_bank.end:
                                try:
                                    enclave = SGXEnclave(task, task, None, self._config.ANALYSIS, self._config.FRAMEWORK, self._config.MAINELF)
                                    enclaves.append(enclave)
                                    raise StopIteration
                                except ValueError:
                                    continue

                    if not self.epc_banks and total_pages == invalid_pages:
                        enclave = SGXEnclave(task, task, None, self._config.ANALYSIS, self._config.FRAMEWORK, self._config.MAINELF)
                        enclaves.append(enclave)
                        raise StopIteration
            except StopIteration:
                pass

        return enclaves

    def find_sgx_enclaves_intel_drv(self, proc_iter, driver):
        """Look for enclaves using Intel SGX drivers structs"""
        enclaves = set()
        for task in proc_iter:

            # Ignore kernel tasks
            if (task.flags & 0x200000):
                continue

            enclaves_s = self.find_sgx_enclaves_host_proc(task, driver)
            for estruct in enclaves_s:
                try:
                    enclave = SGXEnclave(task, estruct, driver, self._config.ANALYSIS, self._config.FRAMEWORK, self._config.MAINELF)
                    enclaves.add(enclave)
                except ValueError:
                    continue

        # Explore other possible enclaves listed belonging to the sgx_encl.encl_list list
        if not enclaves or driver != "isgx":
            return list(enclaves)

        for encl_obj in enclaves.copy():
            encl = encl_obj.estruct
            for nxt_encl in encl.encl_list.list_of_type("sgx_encl_isgx", "encl_list"):
                try:
                    enclave = SGXEnclave(nxt_encl.mm.owner, nxt_encl, driver, self._config.ANALYSIS, self._config.FRAMEWORK, self._config.MAINELF)
                    enclaves.add(enclave)
                except ValueError:
                    continue

        return list(enclaves)

    def find_sgx_enclaves_host_proc(self, task_s, driver_name):
        """Explore the memory space of a process to find SGX enclaves loaded by Intel drivers"""
        sgx_encl_struct = "sgx_encl_" + driver_name
        estructs = []
        for vma in task_s.get_proc_maps():
                # Check if the vm_area_struct is a valid SGX memory area
                if not self.check_sgx_area_struct(task_s, vma):
                    continue

                # struct sgx_encl candidate found
                estructs.append(vma.vm_private_data.dereference_as(sgx_encl_struct))

        return estructs

    def check_sgx_area_struct(self, task_s, vm_area_struct):
        """Check if a vm_area_struct contains a reference to an SGX enclave loaded by Intel drivers"""
        # Ignore regular pages
        if "sgx" not in vm_area_struct.vm_name(task_s).lower():
            return False

        # SGX pages has special VM flags enabled
        vm_flags = vm_area_struct.flags()
        if  "VM_PFNMAP" not in vm_flags or \
            "VM_DONTEXPAND" not in vm_flags or \
            "VM_IO" not in vm_flags:
            return False

        # Ignore pages which point to invalid vm_private_data addresses
        if not vm_area_struct.vm_private_data.is_valid():
            return False

        return True

    def return_task_by_pid_offset(self):
        # Look for specific process
        pid = self._config.PID
        if pid:
            for task in linux_pslist.linux_pslist(self._config).allprocs():
                if task.pid == pid:
                    break
            else:
                print("No process with PID {} found".format(str(pid)))
                return None
        else:
            task = obj.Object("task_struct", offset=self._config.OFFSET, vm = self.addr_space)

        return task

    def show_detailed_info(self, is_isgx):
        task = self.return_task_by_pid_offset()
        if not task:
            return []

        # Find enclaves
        enclaves = self.find_sgx_enclaves_intel_drv([task], "isgx" if is_isgx else "dcap")
        for enclave in enclaves:
            if enclave.einfo["base"] == self._config.EBASE:
                return [enclave]
        else:
            return []

    def dump_enclaves(self):
        print("I dump enclaves?")
        task = self.return_task_by_pid_offset()
        if not task:
            return []

        # Identify all the ELFs which are inside EPC
        elfs = []
        for elf, elf_start, elf_end, soname, needed in task.elfs():
            phy_addr = task.get_process_address_space().vtop(elf_start)
            for epc_bank in self.epc_banks:
                if epc_bank.start <= phy_addr <= epc_bank.end:
                    file_path = linux_common.write_elf_file(self._config.DUMP_DIR, task, elf.v())
                    elfs.append((soname, elf_start, file_path))
                    break

        print(elfs)

        return elfs

    def generator(self, data):
        if self.mode == 0:
            for enclave in data:
                    enclave.performs_long_operations()
                    yield (0, [
                        Address(enclave.parent_task.v()),
                        str(enclave.pinfo["name"]),
                        int(enclave.pinfo["pid"]),
                        Address(enclave.einfo["base"]),
                        int(enclave.einfo["size"]),
                        ",".join(enclave.einfo["flags"]),
                        hex(int(enclave.einfo["xfrm"])),
                        int(enclave.einfo["ssa_size"]),
                        str(enclave.einfo["type"]),
                        enclave.einfo["tcss"],
                        enclave.einfo["mmap"],
                        enclave.einfo["framework"],
                        enclave.einfo["ecreate"],
                        enclave.einfo["interface"]
                        # enclave.einfo["ecalls"],
                        # enclave.einfo["ocalls"]
                    ])
        elif self.mode == 2:
            if not self._config.FORCE:
                for enclave in data:
                    yield (0, [
                        Address(enclave.parent_task.v()),
                        str(enclave.pinfo["name"]),
                        int(enclave.pinfo["pid"]),
                        Address(enclave.einfo["base"]),
                        hex(int(enclave.einfo["size"])),
                        ",".join(enclave.einfo["flags"])
                    ])
            else:
                for enclave in data:
                    yield (0, [
                        Address(enclave.parent_task.v()),
                        str(enclave.pinfo["name"]),
                        int(enclave.pinfo["pid"]),
                        "?",
                        "?",
                        "?"
                    ])
        else:
            for elf in data:
                yield (0, [
                    str(elf[0]),
                    Address(elf[1]),
                    str(elf[2])
                ])

    def unified_output(self, data):
        # FLAVIO: I guess we don't need this
        # if self.mode == 0:
        #     tree = [
        #         ("Offset", Address),
        #         ("Process", str),
        #         ("PID", int),
        #         ("Enclave base", Address),
        #         ("Enclave size", str),
        #         ("Enclave flags", str),
        #         ("XFRM", str),
        #         ("SSA Size", int),
        #         ("Type", str),
        #         ("TCSs", list),
        #         ("Memory areas", list)
        #         ]
        #     return TreeGrid(tree, self.generator(data))

        # el
        if self.mode == 2:
            tree = [
                ("Offset", Address),
                ("Process", str),
                ("PID", int),
                ("Enclave base", Address if not self._config.FORCE else str),
                ("Enclave size", str),
                ("Enclave flags", str),
                ]
            return TreeGrid(tree, self.generator(data))

        else:
            tree = [
                ("Name", str),
                ("Address", Address),
                ("Path", str)
            ]
            return TreeGrid(tree, self.generator(data))


    def render_text(self, outfd, data):

        if self.mode == 0:
            for i, (offset, task_name, task_pid, encl_base, encl_size, encl_flags, encl_xfrm, encl_ssa_size, encl_type, tcss, enclave_mmaps_tags, framework, ecreate, interface) in self.generator(data):

                outfd.write("\n" + "="*80 + "\n")
                outfd.write("Host Process [offset=0x{:x}, name={}, PID: {}]\n".format(offset, task_name, task_pid))
                outfd.write("Enclave [base_address=0x{:x}, size=0x{:x}, flags={}, xfrm={}, ssa size={} type={}]\n".format(encl_base, encl_size, encl_flags, encl_xfrm, encl_ssa_size, encl_type))

                if self._config.ANALYSIS == 'M' or self._config.ANALYSIS == 'B':

                    if tcss:
                        outfd.write("TCS: {}\n".format(" ".join(["0x{:x}".format(t) for t in tcss])))
                    else:
                        outfd.write("TCSs not found\n")

                    outfd.write("Memory Layout:\n")
                    for start, end, permission, tag in enclave_mmaps_tags:
                        if tag:
                            outfd.write("\t0x{:x}-0x{:x} {} [{}]\n".format(start, end, permission, tag))
                        else:
                            outfd.write("\t0x{:x}-0x{:x} {}\n".format(start, end, permission))

                if self._config.ANALYSIS == 'I' or self._config.ANALYSIS == 'B':

                    outfd.write("SGX Framework: {}\n".format(framework))

                    if not ecreate:
                        outfd.write("ECREATE not found\n")
                    else:
                        outfd.write("ECREATE: {}\n".format(" ".join(["0x{:x}".format(t) for t in ecreate])))

                    # if not ecalls:
                    #     outfd.write("ECALL not found\n")
                    # else:
                    #     outfd.write("ECALL: {}\n".format(" ".join(["0x{:x}".format(t) for t in ecalls])))

                    # if not ocalls:
                    #     outfd.write("OCALL not found\n")
                    # else:
                    #     outfd.write("OCALL: {}\n".format(" ".join(["0x{:x}".format(t) for t in ocalls])))

                    if interface:
                        for x in interface:
                            ebase = x["ebase"]
                            ecalls = x["ecall"]
                            ocalls = x["ocall"]

                            if ebase is None:
                                outfd.write("EBASE not found\n")
                            else:
                                outfd.write("EBASE = 0x{:x}\n".format(ebase))

                            if not ecalls:
                                outfd.write("ECALL not found\n")
                            else:
                                outfd.write("ECALL: {}\n".format(" ".join(["0x{:x}".format(t) for t in ecalls])))

                            if not ocalls:
                                outfd.write("OCALL not found\n")
                            else:
                                outfd.write("OCALL: {}\n".format(" ".join(["0x{:x}".format(t) for t in ocalls])))

                            outfd.write("")
                    else:
                        outfd.write("Interfaces not found\n")


        else:
            # THIS IS THE STANDARD BEHAVIOR OF COMMAND.PY, IT FALLBACKS TO unified_output()
            self._render(outfd, TextRenderer(self.text_cell_renderers, sort_column = self.text_sort_column,
                                         config = self._config), data)

    def render_json(self, outfd, data):

        if self.mode == 0:
            # print "json verbose output"
            lst = []
            for i, (offset, task_name, task_pid, encl_base, encl_size, encl_flags, encl_xfrm, encl_ssa_size, encl_type, tcss, enclave_mmaps_tags, framework, ecreate, interface) in self.generator(data):

                record = {}
                record["offset"] = offset
                record["task_name"] = task_name
                record["task_pid"] = task_pid
                record["encl_base"] = encl_base
                record["encl_size"] = encl_size
                record["encl_flags"] = encl_flags
                record["encl_xfrm"] = encl_xfrm
                record["encl_ssa_size"] = encl_ssa_size
                record["encl_type"] = encl_type
                record["tcss"] = tcss
                record["enclave_mmaps_tags"] = enclave_mmaps_tags
                record["framework"] = framework
                record["ecreate"] = list(ecreate)
                record["interface"] = interface
                # record["ecalls"] = list(ecalls)
                # record["ocalls"] = list(ocalls)

                lst.append(record)

            json.dump(lst, outfd)
        else:
            # THIS IS THE STANDARD BEHAVIOR OF COMMAND.PY, IT FALLBACKS TO unified_output()
            try:
                self._render(outfd, JSONRenderer(), data)
            except NotImplementedError, why:
                print why
            except TypeError, why:
                print why
