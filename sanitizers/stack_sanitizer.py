#!/usr/bin/env python3

#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# 2023-12-19
# Author: readermall and liuyi
#

import argparse
import sys
import random
import re
from dataclasses import dataclass
from enum import IntEnum

sys.path.append("../qiling")

from qiling import Qiling
from qiling.core_hooks_types import HookRet
from qiling.const import *
from capstone import Cs
from .sanitizer_utils import *

@dataclass
class Region:
    start:int
    end:int
    name:str
    hook:HookRet

    def __eq__(self, other):
        return self.name==other.name

class StackSanitizer(DebugUtil):
    def __init__(self, ql: Qiling, detect_types=QL_DETECT_TYPES.ENABLE_STACK_ALL, exception_class=DefaultException, debug_level=QL_DEBUG_LEVEL.DEBUG_OFF):

        super().__init__(debug_level)
        self.__ql = ql
        self.__exception_class = exception_class(debug_level)
        self.__detect_types = detect_types

        #
        self.__flag_lr_pushd = False
        self.__flag_lr_popd = False
        self.__push_depth = 0

        #
        self.__stack_address_lr = 0
        self.__stack_top_prepop = 0
        self.__stack_top_prepush = 0
        
        # 
        self.__stack_size = 4
        self.__arch_endian = "little"
        self.__map = {}
        self.__regions=[]

        # mips special
        self.__mips_mflr = None

        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        if ql.arch.endian != QL_ENDIAN.EL:
            self.__arch_endian = "big"
        if ql.arch.type in [QL_ARCH.X8664, QL_ARCH.ARM64]:
            self.__stack_size = 8
        for info_line in ql.mem.get_formatted_mapinfo():
           self.default_debug(info_line, debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        for info_line in ql.mem.get_mapinfo():
            #
            # We monitor the data on the stack to avoid it being executed
            #
            if "[stack]" == info_line[3] and self.__detect_types & QL_DETECT_TYPES.ENABLE_STACK_NX:
                stack_begin = info_line[0]
                stack_end = info_line[1]
                ql.hook_mem_fetch(self.__exception_class.exec_stack_handler, begin=stack_begin, end=stack_end)
            #
            # We monitor the data of the program code snippet and check each instruction before it is executed
            #
            if "r-x" == info_line[2] and ql.argv[0].split("/")[-1] == info_line[4].split("/")[-1] and self.__detect_types & QL_DETECT_TYPES.ENABLE_STACK_CANARY_WRITE:
                user_code_begin = info_line[0]
                user_code_end = info_line[1]
                ql.hook_code(self.__code_diassembler, user_data=ql.arch.disassembler, begin=user_code_begin, end=user_code_end)

            #
            # We also add the image of the ld.linux to the detection
            #
            if "r-x" == info_line[2] and ql.argv[0].split("/")[-1] != info_line[4].split("/")[-1] and self.__detect_types & QL_DETECT_TYPES.ENABLE_STACK_CANARY_WRITE:
                user_code_begin = info_line[0]
                user_code_end = info_line[1]
                region = self.__get_region(info_line[3])
                if not region:
                    code_hook = ql.hook_code(self.__code_diassembler, user_data=ql.arch.disassembler, begin=user_code_begin,end=user_code_end)
                    self.__regions.append(Region(user_code_begin, user_code_end,info_line[3], code_hook))

    #
    # get current stack frame
    #
    def __get_stack_data(self, ql: Qiling, depth: int):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        self.default_debug("\t" + "The current stack frame :", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        stack_value_format = '{:0' + str(self.__stack_size * 2) + 'x}'
        for i in range(0, self.__stack_size * depth, self.__stack_size):
            self.default_debug("\t\t" + "$sp+0x" + "{:02x}".format(i) + "  :  " + hex(ql.arch.regs.arch_sp + i) + "  ==>  " + stack_value_format.format(ql.stack_read(i)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

    #
    # get current stack frame
    #
    def __read_from_address(self, ql: Qiling, address: int, size: int):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        address = (address + 3) // 4 * 4
        size = (size + 15) // 16 * 16
        read_bytes = ql.mem.read(address, size)
        self.default_debug("\t" + hex(address) + " value is : \n", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        for i in range(0, size // 16, 16):
            for j in range(0, 16, 4):
                self.default_debug("\t\t" + "$sp+0x" + "{:02x}".format(i) + "  :  " + hex(read_bytes[i * 16 + j]), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

    #
    # get current registers value
    #
    def __get_regs_value(self, ql: Qiling):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        self.default_debug("\t" + "The value of the current register :", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        for reg in ql.arch.regs.register_mapping:
            self.default_debug("\t\t" + f"{reg:16s}" + " : " + hex(ql.arch.regs.read(reg)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

    def __get_region(self,name):
        for region in self.__regions:
            if region.name == name:
                return region
        return None
    
    #
    # Used to identify the first number from a string
    #
    def __extract_item(self, p: str, s: str, n: int):
        #print(p, "123")
        match = re.search(p, s)
        if match:
            return match.group(n)
        return None

    def __stack_read_handler(self, ql: Qiling, access: int, address: int, size: int, value: int):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        self.default_debug("\tpre pop lr : " + hex(address) + " ==> " + hex(int.from_bytes(ql.mem.read(address, self.__stack_size), byteorder=self.__arch_endian)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        self.__ql.hook_del(self.__map[address][0])
        self.__ql.hook_del(self.__map[address][1])
        del self.__map[address]
        self.__push_depth = self.__push_depth - 1
        self.default_debug("push depth : " + hex(self.__push_depth), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        self.default_debug("\tmove hook : " + hex(address), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        
    #
    # Code disassembler, which is used to disassemble code in a given range
    # find the assembly statement of interest in it, and its address
    #
    def __code_diassembler(self, ql: Qiling, address: int, size: int, md: Cs) -> None:
        #for info_line in ql.mem.get_formatted_mapinfo():
        #    self.default_debug(info_line)
        names = []
        for info_line in ql.mem.get_mapinfo():
            user_code_begin = info_line[0]
            user_code_end = info_line[1]
            if "r-x" == info_line[2] and ql.argv[0].split("/")[-1] != info_line[4].split("/")[-1] and self.__detect_types & QL_DETECT_TYPES.ENABLE_STACK_CANARY_WRITE:
                names.append(info_line[3])
                region = self.__get_region(info_line[3])
                if not region:
                    code_hook = ql.hook_code(self.__code_diassembler, user_data=ql.arch.disassembler, begin=user_code_begin,end=user_code_end)
                    self.__regions.append(Region(user_code_begin, user_code_end,info_line[3], code_hook))
                elif region.start!=user_code_begin or region.end!=user_code_end:
                    self.__regions.remove(region)
                    ql.hook_del(region.hook)
                    code_hook = ql.hook_code(self.__code_diassembler, user_data=ql.arch.disassembler,begin=user_code_begin, end=user_code_end)
                    self.__regions.append(Region(user_code_begin, user_code_end, info_line[3], code_hook))
        for region in self.__regions:
            if region.name not in names:
                self.__regions.remove(region)
                ql.hook_del(region.hook)

        buf = ql.mem.read(address, size)
        insn = next(md.disasm(buf, address))
        self.default_debug("\t" + f'{insn.address:#016x} : {insn.mnemonic:24s} {insn.op_str}', debug_level=QL_DEBUG_LEVEL.DEBUG_EVERY)

        if self.__flag_lr_pushd == True:
            self.default_debug("\t" + f'{insn.address:#016x} : {insn.mnemonic:24s} {insn.op_str}', debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.default_debug("\tpost push lr : " + hex(self.__stack_address_lr) + " ==> " + hex(int.from_bytes(ql.mem.read(self.__stack_address_lr, self.__stack_size), byteorder=self.__arch_endian)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.__flag_lr_pushd = False
            self.__push_depth = self.__push_depth + 1
            self.default_debug("push depth : " + hex(self.__push_depth), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            # We monitor read and write operations at the canary location
            write_hook = ql.hook_mem_write(self.__exception_class.stack_write_handler, begin=self.__stack_address_lr, end=self.__stack_address_lr + self.__stack_size - 1)
            self.__map[self.__stack_address_lr] = write_hook

            if ql.arch.type == QL_ARCH.PPC:
                read_hook = ql.hook_mem_read(self.__stack_read_handler, begin=self.__stack_address_lr, end=self.__stack_address_lr + self.__stack_size - 1)
                self.__map[self.__stack_address_lr] = [write_hook, read_hook]
            
            self.default_debug("\thook area : " + hex(self.__stack_address_lr), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        if self.__flag_lr_popd == True:
            self.default_debug("\t" + f'{insn.address:#016x} : {insn.mnemonic:24s} {insn.op_str}', debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.default_debug("\tpost pop lr : " + hex(self.__stack_address_lr) + " ==> " + hex(int.from_bytes(ql.mem.read(self.__stack_address_lr, self.__stack_size), byteorder=self.__arch_endian)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.__flag_lr_popd = False
            
            #
            # arm is a bit special, there are conditional pop instructions, such as popeq
            # if the conditions are not met, it will not pop, so it needs to be judged more
            #
            if ql.arch.type == QL_ARCH.ARM and self.__stack_top_prepop != ql.arch.regs.arch_sp:
                self.__stack_address_lr = ql.arch.regs.arch_sp - self.__stack_size
                self.__ql.hook_del(self.__map[self.__stack_address_lr])
                del self.__map[self.__stack_address_lr]
                self.__push_depth = self.__push_depth - 1
                self.default_debug("\tmove hook : " + hex(self.__stack_address_lr), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            elif ql.arch.type == QL_ARCH.X86 or ql.arch.type == QL_ARCH.X8664:
                self.__stack_address_lr = ql.arch.regs.arch_sp - self.__stack_size
                self.__ql.hook_del(self.__map[self.__stack_address_lr])
                del self.__map[self.__stack_address_lr]
                self.__push_depth = self.__push_depth - 1
                self.default_debug("\tmove hook : " + hex(self.__stack_address_lr), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            
            # MIPS allows LRs to be stored in the stack and taken out multiple times, which we only del for the first time here
            elif ql.arch.type == QL_ARCH.MIPS:
                try:
                    self.__ql.hook_del(self.__map[self.__stack_address_lr])
                    del self.__map[self.__stack_address_lr]
                    self.__push_depth = self.__push_depth - 1
                    self.default_debug("\tmove hook : " + hex(self.__stack_address_lr), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
                except:
                    pass

            self.default_debug("push depth : " + hex(self.__push_depth), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        #
        # If the operator of the assembly statement is push, a canary word is inserted
        #
        if ql.arch.type == QL_ARCH.ARM and ("push" == insn.mnemonic and "lr" in insn.op_str or "str" == insn.mnemonic and "lr, [sp, #-4]!" == insn.op_str)or \
                ql.arch.type == QL_ARCH.ARM64 and insn.mnemonic == "push" and "lr" in insn.op_str or \
                ql.arch.type == QL_ARCH.X86 and insn.mnemonic == "call" or \
                ql.arch.type == QL_ARCH.X8664 and insn.mnemonic == "call" or \
                ql.arch.type == QL_ARCH.RISCV and insn.mnemonic == "call" or \
                ql.arch.type == QL_ARCH.RISCV64 and insn.mnemonic == "c.addi16sp" and "sp" in insn.op_str and "-" in insn.op_str or \
                ql.arch.type == QL_ARCH.MIPS and insn.mnemonic == "sw" and self.__extract_item(r'\$ra, (0x[a-fA-F0-9]+)\(\$([sf]p)\)', insn.op_str, 1) or \
                ql.arch.type == QL_ARCH.PPC and self.__mips_mflr != None and insn.mnemonic == "stw" and self.__extract_item(self.__mips_mflr, insn.op_str, 2):

            self.default_debug("\t" + f'{insn.address:#016x} : {insn.mnemonic:24s} {insn.op_str}', debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.__flag_lr_pushd = True
            self.__stack_address_lr = ql.arch.regs.arch_sp - self.__stack_size

            if ql.arch.type == QL_ARCH.MIPS:
                offset = int(self.__extract_item(r'\$ra, (0x[a-fA-F0-9]+)\(\$([sf]p)\)', insn.op_str, 1), 16)
                register = self.__extract_item(r'\$ra, (0x[a-fA-F0-9]+)\(\$([sf]p)\)', insn.op_str, 2)
                if register == 'fp':
                    self.__stack_address_lr = ql.arch.regs.read("r30") + offset
                else:
                    self.__stack_address_lr = ql.arch.regs.arch_sp + offset

                self.default_debug("\tpre push lr : " + hex(self.__stack_address_lr) + " ==> " + hex(int.from_bytes(ql.mem.read(self.__stack_address_lr, self.__stack_size), byteorder=self.__arch_endian)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
                self.default_debug("\tlr value : " + hex(ql.arch.regs.read("ra")), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            if ql.arch.type == QL_ARCH.PPC:
                offset = int(self.__extract_item(self.__mips_mflr, insn.op_str, 2), 16)
                self.__stack_address_lr = ql.arch.regs.arch_sp + offset
                self.default_debug("\tpre push lr : " + hex(self.__stack_address_lr) + " ==> " + hex(int.from_bytes(ql.mem.read(self.__stack_address_lr, self.__stack_size), byteorder=self.__arch_endian)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
                self.default_debug("\tlr value : " + hex(ql.arch.regs.read(self.__extract_item(self.__mips_mflr, insn.op_str, 1))), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
                self.__mips_mflr = None


        # If the operator of the assembly statement is pop, a canary word is remove
        #
        #
        if self.__push_depth > 0:
            if ql.arch.type == QL_ARCH.ARM and "pop" in insn.mnemonic and ("pc" in insn.op_str or "lr" in insn.op_str) or\
                    ql.arch.type == QL_ARCH.ARM64 and insn.mnemonic == "pop" and "pc" in insn.op_str or \
                    ql.arch.type == QL_ARCH.X86 and insn.mnemonic in ["ret", "retn"] or \
                    ql.arch.type == QL_ARCH.X8664 and insn.mnemonic in ["ret", "retn", "repz ret", "rep ret"] or \
                    ql.arch.type == QL_ARCH.RISCV and insn.mnemonic == "call" or \
                    ql.arch.type == QL_ARCH.RISCV64 and insn.mnemonic == "c.addi16sp" and "sp" in insn.op_str and "-" not in insn.op_str or \
                    ql.arch.type == QL_ARCH.MIPS and insn.mnemonic == "lw" and self.__extract_item(r'\$ra, (0x[a-fA-F0-9]+)\(\$([sf]p)\)', insn.op_str, 1):
                #
                # Instruction set agnostic code is written here
                #
                self.default_debug("\t" + f'{insn.address:#016x} : {insn.mnemonic:24s} {insn.op_str}', debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
                self.__flag_lr_popd = True

                #
                # The code for the instruction set is written here
                #
                if ql.arch.type == QL_ARCH.MIPS:
                    offset = int(self.__extract_item(r'\$ra, (0x[a-fA-F0-9]+)\(\$([sf]p)\)', insn.op_str, 1), 16)
                    register = self.__extract_item(r'\$ra, (0x[a-fA-F0-9]+)\(\$([sf]p)\)', insn.op_str, 2)
                    if register == 'fp':
                        self.__stack_address_lr = ql.arch.regs.read("r30") + offset
                    else:
                        self.__stack_address_lr = ql.arch.regs.arch_sp + offset

                    self.default_debug("\tpre pop lr : " + hex(self.__stack_address_lr) + " ==> " + hex(int.from_bytes(ql.mem.read(self.__stack_address_lr, self.__stack_size), byteorder=self.__arch_endian)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

                if ql.arch.type == QL_ARCH.ARM:
                    self.__stack_top_prepop = ql.arch.regs.arch_sp

        #
        if ql.arch.type == QL_ARCH.PPC and insn.mnemonic == "mflr":
            self.default_debug("\t" + f'{insn.address:#016x} : {insn.mnemonic:24s} {insn.op_str}', debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.__mips_mflr = f"({insn.op_str}), (0x[a-fA-F0-9]+)\\(r1\\)"
            self.default_debug("\tpattern: " + self.__mips_mflr, debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
