#!/usr/bin/env python3

#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# 2023-12-19
# Author: readermall and liuyi
#

import argparse
import re
import sys
import threading

sys.path.append("../qiling")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_CALL_BLOCK, QL_VERBOSE
from qiling.os.const import *
from enum import Enum, Flag, IntEnum
from bitarray import bitarray
from capstone import Cs
from .sanitizer_utils import *

#
# A memory region class that records various properties of a memory region
#
class MemRegion:
    def __init__(self, address, size, canary_size, method) -> None:
        self.start_address = address
        self.size = size
        self.end_address = self.start_address + self.size - 1
        self.shadow = self.__init_shadow()
        self.hooks = []
        self.canary_size = canary_size
        # Document the methods used to request and free memory
        self.method = method
        self.is_print = False

    def __repr__(self) -> str:
        return f"mem_region : {self.start_address:#x}-{self.end_address:#x} {self.shadow}"

    def __init_shadow(self):
        shadow = bitarray(self.size)
        shadow.setall(0)
        return shadow

    def read(self, address, size):
        start = address - self.start_address

        if self.is_print == True:
            for offset in range(start, start + size):
                if self.shadow[offset] ^ 1:
                    print(f"uninitialized memory read.\n{self} - {self.start_address + offset:#x}")
        else:
            for offset in range(start, start + size):
                if self.shadow[offset] ^ 1:
                    raise InternalException(None, f"uninitialized memory read.\n{self} - {self.start_address + offset:#x}")

    def write(self, address, size):
        start = address - self.start_address

        for offset in range(start, start + size):
            self.shadow[offset] |= 1

    def addHooks(self, hooks):
        self.hooks.extend([h for h in hooks if h])

#
# A memory region management class that manages memory regions from their lifecycle
#
class MemRegionManage:
    def __init__(self) -> None:
        self.__regions = []

    @property
    def regions(self):
        return self.__regions
    
    def __repr__(self) -> str:
        regions = "\n".join(f"  - {repr(region)}" for region in self.regions)
        return f"memRegionManage : \n{regions}"

    def add(self, mem_region: MemRegion):
        # check
        addr = mem_region.start_address
        size = mem_region.size

        for region in self.regions:
            # has overlapped region
            if region.start_address <= addr <= region.end_address or region.start_address <= addr + size - 1 <= region.end_address:
                raise InternalException(None, "overlapped memory.")
        self.regions.append(mem_region)

    def remove(self, mem_region: MemRegion):
        self.regions.remove(mem_region)

    def find(self, addr, size):
        for region in self.regions:
            if addr >= region.start_address and addr + size - 1 <= region.end_address:
                return region
        return None

    def equal(self, addr):
        for region in self.regions:
            if addr == region.start_address:
                return region
        return None

    def __iter__(self):
        return iter(self.regions)

#
# Heap memory sanitizer to detect various heap memory usage errors
#
class HeapSanitizer(DebugUtil):

    __CANARY_SIZE = 4
    __NEW = "new"
    __NEW_ARRAY = "new[]"
    __ALLOC = "malloc/calloc/realloc"

    def __init__(self, ql: Qiling, detect_types, exception_class = DefaultException, debug_level = 0) -> None:
        
        super().__init__(debug_level)
        self.__ql = ql

        # Thread-safe locks
        self.__lock_alloc = threading.Lock()
        self.__lock_free = threading.Lock()

        # Used to record parameters
        self.__user_size = None
        self.__para_addr = None
        self.__temp_canary_size = None

        self.__exception_class = exception_class(debug_level)
        self.__mem_regions = MemRegionManage()
        self.__exception_class.mem_regions = self.__mem_regions

        # Detect type and debug type
        self.__detect_types = detect_types
        
        #
        # Every enter and exit is locked to keep the thread safe
        #
        self.__ql.os.set_api('malloc', self.__on_malloc_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('malloc', self.__on_malloc_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('calloc', self.__on_calloc_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('calloc', self.__on_calloc_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('realloc', self.__on_realloc_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('realloc', self.__on_realloc_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('free', self.__on_free_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('free', self.__on_free_exit, QL_INTERCEPT.EXIT)

        #
        # _Znwj is new in libc, this is crazy
        #
        self.__ql.os.set_api('_Znwj', self.__on_new_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('_Znwj', self.__on_new_exit, QL_INTERCEPT.EXIT)
        
        #
        # _Znaj is new[] in libc
        #
        self.__ql.os.set_api('_Znaj', self.__on_new_array_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('_Znaj', self.__on_new_array_exit, QL_INTERCEPT.EXIT)
        
        #
        # _ZdlPvj is delete in libc
        #
        self.__ql.os.set_api('_ZdlPvj', self.__on_delete_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('_ZdlPvj', self.__on_delete_exit, QL_INTERCEPT.EXIT)
        
        #
        # _ZdaPv is delete[] in libc
        #
        self.__ql.os.set_api('_ZdaPv', self.__on_delete_array_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('_ZdaPv', self.__on_delete_array_exit, QL_INTERCEPT.EXIT)


    def mem_write_handler(self, ql, access, addr, size, value):
        ql.log.info(f"write : {addr:#x}, {size}, {value}")
        region = self.__mem_regions.find(addr = addr, size = size)
        if not region:
            raise InternalException(ql, f"possibly out-of-bounds element is accessed.\n {self.__mem_regions} \n AccessRegion : {addr:#x}, {size}")
        else:
            region.write(addr, size)

    def mem_read_handler(self, ql, access, addr, size, value):
        ql.log.info(f"read : {addr:#x}, {size}, {value}")
        region = self.__mem_regions.find(addr = addr, size = size)
        if not region:
            raise InternalException(ql, f"possibly out-of-bounds element is accessed.\n {self.__mem_regions} \n AccessRegion : {addr:#x}, {size}")
        else:
            region.read(addr, size)
    #
    # This method is called when exiting all memory alloc methods
    # which uniformly monitors memory and tracks heap memory throughout its lifecycle
    #
    def __on_alloc_exit(self, ql: Qiling, size: int, canary_size: int, method: str):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            real_address = ql.os.fcall.cc.getReturnValue()
            self.default_debug("real address: " + str(hex(real_address)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            address = real_address + canary_size
            #
            # Each region has the following structure, with a red area at both ends and memory for the program in the middle
            # | red area 1 | user memory | red area 2 |
            # For red area 1, we monitor its read and write behavior to detect out-of-bounds
            #
            start_addr = address - canary_size
            end_addr = address - 1
            self.default_debug("red area1 start_addr: " + str(hex(start_addr)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.default_debug("red area1 end_addr: " + str(hex(end_addr)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            area1_write_hook = ql.hook_mem_write(self.__exception_class.bo_handler, begin=start_addr, end=end_addr) if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_OB else None
            area1_read_hook = ql.hook_mem_read(self.__exception_class.oob_handler, begin=start_addr, end=end_addr) if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_OOB else None

            #
            # For user memory, we monitor its read and write behavior to detect out-of-bounds
            #
            start_addr = address
            end_addr = address + size - 1
            self.default_debug("user memory start_addr: " + str(hex(start_addr)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.default_debug("user memory end_addr: " + str(hex(end_addr)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            mem_write_hook = ql.hook_mem_write(self.mem_write_handler, begin=start_addr, end=end_addr) if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_UINIT else None
            mem_read_hook = ql.hook_mem_read(self.mem_read_handler, begin=start_addr, end=end_addr) if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_UINIT else None

            #
            # For red area 2, we monitor its read and write behavior to detect out-of-bounds
            #  
            start_addr = address + size
            end_addr = start_addr + canary_size - 1
            self.default_debug("red area2 start_addr: " + str(hex(start_addr)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.default_debug("red area2 end_addr: " + str(hex(end_addr)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            area2_write_hook = ql.hook_mem_write(self.__exception_class.bo_handler, begin=start_addr, end=end_addr) if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_OB else None
            area2_read_hook = ql.hook_mem_read(self.__exception_class.oob_handler, begin=start_addr, end=end_addr) if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_OOB else None

            mem_region = MemRegion(address, size, canary_size, method)
            mem_region.addHooks([area1_write_hook, area1_read_hook, mem_write_hook, mem_read_hook, area2_write_hook, area2_read_hook])
            self.__mem_regions.add(mem_region)

            self.default_debug("address: " + str(hex(address)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            ql.os.fcall.cc.setReturnValue(address)

            return address
        except Exception as e:
            raise e

    #
    # When new is called, we hijac its exit, modifying its arguments
    # The original arguments is address, we modify to readdress = address + self.__temp_canary_size
    #
    def __on_new_exit(self,ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_alloc_exit(ql, self.__user_size, self.__temp_canary_size, self.__NEW)
            
        finally:
            self.__lock_alloc.release()
    #
    # When new is called, we hijac its enter, modifying its arguments
    # The original arguments is size, we modify to resize = size + 2 * self.__temp_canary_size
    #
    def __on_new_enter(self,ql: Qiling):
        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            size = params['size']

            self.__user_size = size
            self.__temp_canary_size = self.__CANARY_SIZE

            resize = size + 2 * self.__temp_canary_size
            self.default_debug("resize: " + str(hex(resize)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            
            ql.os.fcall.writeParams(((SIZE_T, resize),))
            return resize
        except Exception as e:
            self.__lock_alloc.release()
            raise e


    #
    # When new[] is called, we hijac its exit, modifying its arguments
    # The original arguments is address, we modify to readdress = address + self.__temp_canary_size
    #
    def __on_new_array_exit(self,ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_alloc_exit(ql, self.__user_size, self.__temp_canary_size, self.__NEW_ARRAY)

        finally:
            self.__lock_alloc.release()

    #
    # When new[] is called, we hijac its enter, modifying its arguments
    # The original arguments is size, we modify to resize = size + 2 * self.__temp_canary_size
    #
    def __on_new_array_enter(self, ql: Qiling):
        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            size = params['size']
            #
            # Record the parameters
            #
            self.__user_size = size
            self.__temp_canary_size = self.__CANARY_SIZE
            
            #
            # modify to resize = size + 2* self.__temp_canary_size
            #
            resize = size + 2 * self.__temp_canary_size
            self.default_debug("resize: " + str(hex(resize)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            ql.os.fcall.writeParams(((SIZE_T, resize),))
            return resize
        except Exception as e:
            self.__lock_alloc.release()
            raise e

    #
    # When malloc is called, we hijac its exit, modifying its arguments
    # The original arguments is address, we modify to readdress = address + self.__temp_canary_size
    #
    def __on_malloc_exit(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_alloc_exit(ql, self.__user_size, self.__temp_canary_size, self.__ALLOC)

        finally:
            self.__lock_alloc.release()

    #
    # When malloc is called, we hijack its enter, modifying its arguments
    # The original arguments is size, we modify to resize = size + 2* self.__temp_canary_size
    #
    def __on_malloc_enter(self, ql: Qiling):
        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            size = params['size']
            #
            # Record the parameters
            #
            self.__user_size = size
            self.__temp_canary_size = self.__CANARY_SIZE
            #
            # modify to resize = size + 2* self.__temp_canary_size
            #
            resize = size + 2 * self.__temp_canary_size
            self.default_debug("resize: " + str(hex(resize)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            ql.os.fcall.writeParams(((SIZE_T, resize),))
            return resize
        except Exception as e:
            self.__lock_alloc.release()
            raise e
    #
    # When realloc is called, we hijack its exit, modifying its arguments
    # The original arguments is address, we modify to readdress = address + self.__temp_canary_size
    #
    def __on_realloc_exit(self,ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_alloc_exit(ql, self.__user_size, self.__temp_canary_size, self.__ALLOC)

        finally:
            self.__lock_alloc.release()

    #
    # When realloc is called, we hijack its enter, modifying its arguments
    # The original arguments is address and size, we modify to size
    #
    def __on_realloc_enter(self, ql: Qiling):
        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'address': int, 'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            address = params['address']
            size = params['size']
            #
            # Remove the hook for memory so that it can be released normally
            #
            region = self.__mem_regions.equal(address)
            if not region:
                self.__exception_class.bad_free_handler(ql, address)
                return False

            self.__mem_regions.remove(region)
            for hook in region.hooks:
                ql.hook_del(hook)
            #
            # Record the parameters
            #
            self.__user_size = size
            self.__temp_canary_size = self.__CANARY_SIZE
            #
            # Modify the address and size parameters to make the realloc function work properly
            #
            readdress = address - region.canary_size
            resize = size + 2 * self.__temp_canary_size
            self.default_debug("address: " + str(hex(readdress)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.default_debug("resize: " + str(hex(resize)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            ql.os.fcall.writeParams(((POINTER,readdress),(SIZE_T, resize)))
            return readdress, resize
        except Exception as e:
            self.__lock_alloc.release()
            raise e
    #
    # When calloc is called, we hijack its exit, modifying its arguments
    # The original arguments is address, we modify to address + canary_size
    #
    def __on_calloc_exit(self,ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_alloc_exit(ql, self.__user_size, self.__temp_canary_size, self.__ALLOC)

        finally:
            self.__lock_alloc.release()
    
    #
    # When calloc is called, we hijack its enter, modifying its arguments
    # The original arguments are nitems and size, we modify to nitems + 2 and size 
    #
    def __on_calloc_enter(self,ql: Qiling):
        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'nitems': int, 'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            size = params['size']
            nitems = params['nitems']
            
            renitems = nitems + 2
            self.__user_size = size * nitems
            self.__temp_canary_size = size

            self.default_debug("nitems: " + str(hex(renitems)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.default_debug("size: " + str(hex(size)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            ql.os.fcall.writeParams(((SIZE_T, renitems), (SIZE_T, size)))

            params = ql.os.resolve_fcall_params({'nitems': int, 'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            return renitems, size

        except Exception as e:
            self.__lock_alloc.release()
            raise e


    #
    # This method is called when entering all memory release methods
    #
    def __on_release_enter(self, ql: Qiling, alloc_method: str, free_method: str):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'address': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            address = params['address']
            self.__para_addr = address

            #
            # Remove the hook for memory so that it can be released normally
            #
            region = self.__mem_regions.equal(address)
            if not region:
                self.__exception_class.bad_free_handler(ql, address)
                return False

            for hook in region.hooks:
                ql.hook_del(hook)

            #
            # Check whether the application method matches the release method
            #
            if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_MISMATCH and region.method != alloc_method:
                self.__exception_class.bad_free_method_hander(ql, region.method, free_method)
                return False

            readdress = address - region.canary_size
            self.default_debug("readdress : " + str(hex(readdress)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            ql.os.fcall.writeParams(((POINTER, readdress),))
            return readdress
        except Exception as e:
            raise e


    #
    # When free is called, we hijack its enter
    #
    def __on_free_enter(self, ql: Qiling):
        try:
            self.__lock_free.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_release_enter(ql, self.__ALLOC, "free")
        except Exception as e:
            self.__lock_free.release()
            raise e
    #
    # When delete is called, we hijack its enter
    #
    def __on_delete_enter(self, ql: Qiling):
        try:
            self.__lock_free.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_release_enter(ql, self.__NEW, "delete")
        except Exception as e:
            self.__lock_free.release()
            raise e
    #
    # When delete[] is called, we hijack its enter
    #
    def __on_delete_array_enter(self, ql: Qiling):
        try:
            self.__lock_free.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_release_enter(ql, self.__NEW_ARRAY, "delete[]")
        except Exception as e:
            self.__lock_free.release()
            raise e

    #
    # This method is called when exiting all memory release methods
    #
    def __on_release_exit(self, ql: Qiling):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        self.default_debug("para_addr : " + str(hex(self.__para_addr)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        region = self.__mem_regions.equal(self.__para_addr)
        if not region:
            self.__exception_class.bad_free_handler(ql, self.__para_addr)
            return False

        self.__mem_regions.remove(region)
        if self.__detect_types & QL_DETECT_TYPES.ENABLE_HEAP_UAF:
            ql.hook_mem_valid(self.__exception_class.uaf_handler, begin=region.start_address, end=region.start_address + region.size - 1)
        return True
    #
    # When free is called, we hijack its exit
    #
    def __on_free_exit(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_release_exit(ql)
        finally:
            self.__lock_free.release()
    #
    # When delete is called, we hijack its exit
    #
    def __on_delete_exit(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_release_exit(ql)
        finally:
            self.__lock_free.release()
    #
    # When delete[] is called, we hijack its exit
    #
    def __on_delete_array_exit(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            return self.__on_release_exit(ql)
        finally:
            self.__lock_free.release()

