#!/usr/bin/env python3

#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# 2023-12-19
# Author: readermall and liuyi
#

import sys
from dataclasses import dataclass
from enum import IntEnum
import threading
from typing import Any

sys.path.append("../qiling")

from qiling import Qiling
from qiling.const import *
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from .sanitizer_utils import *

class ThreadLockSet(DebugUtil):
    def __init__(self, debug_level):

        super().__init__(debug_level)
        self.map = {}

    def add_lock(self, tid, lock):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        self.default_debug(f"pre add lock {hex(lock)} to thread {int(tid)}, {self.map[tid]}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        if tid in self.map:
            self.map[tid].add(lock)
        else:
            self.map[tid] = {lock}
        self.default_debug(f"post add lock {hex(lock)} to thread {int(tid)}, {self.map[tid]}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

    def get_lockset(self, tid):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        self.default_debug(f"thread {int(tid)} lockset is {self.map.get(tid, set())}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        return self.map.get(tid, set())

    def remove_lock(self, tid, lock):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        self.default_debug(f"pre remove lock from thread {int(tid)}, {self.map.get(tid, set())}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        self.map[tid].remove(lock)
        self.default_debug(f"post remove lock from thread {int(tid)}, {self.map.get(tid, set())}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)


class VariableLockSet(DebugUtil):
    def __init__(self, debug_level):

        super().__init__(debug_level)
        self.map = {}

    def access(self, address, thread_lockset):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        self.default_debug(f"access variable {hex(address)}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        if address not in self.map:
            self.map[address] = thread_lockset.copy()
            self.default_debug(f"variable {hex(address)} initialization as {self.map[address]}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        else:
            self.map[address]
            self.default_debug(f"{self.map[address]} intersection {thread_lockset}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO, end="")
            self.map[address] = self.map[address].intersection(thread_lockset)
            self.default_debug(f" is {self.map[address]}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        return self.map[address]


class VariableThreadSet(DebugUtil):
    def __init__(self, debug_level):

        super().__init__(debug_level)
        self.map = {}

    def add_thread(self, address, tid):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        
        if address not in self.map:
            self.default_debug(f"pre add thread to variable {hex(address)}, {self.map.get(address, set())}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.map[address] = {tid}
        else:
            self.default_debug(f"pre add thread {int(tid)} to variable {hex(address)}, {self.map[address]}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.map[address].add(tid)

        self.default_debug(f"post add thread {int(tid)} to variable {hex(address)}, {self.map[address]}, len is {len(self.map[address])}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        return len(self.map[address])


class VariableHookSet(DebugUtil):
    def __init__(self, debug_level):

        super().__init__(debug_level)
        self.map = {}

    def add_variable(self, address, hooks):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        
        self.default_debug(f"pre add variable {hex(address)} to {self.map}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        self.map[address] = hooks
        self.default_debug(f"post add variable {hex(address)} to {self.map}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

    def remove_variable(self,address,ql):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        self.default_debug(f"pre remove variable {hex(address)} from {self.map}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
        
        for h in self.map[address]:
            ql.hook_del(h)
        del self.map[address]

        self.default_debug(f"post remove variable {hex(address)} from {self.map}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)


class SharedInterface(DebugUtil):
    def __init__(self, debug_level):

        super().__init__(debug_level)
        self.thread_lockset = ThreadLockSet(debug_level)
        self.variable_lockset = VariableLockSet(debug_level)
        self.variable_threadset = VariableThreadSet(debug_level)

    def read_hook(self, ql: Qiling, access: int, address: int, size: int, value: int, *context: Any):
        #return
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        thread_id = ql.os.thread_management.cur_thread.id
        self.default_debug(f"{thread_id} read {hex(address)}, size {int(size)}, value {int(value)}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        if not self.variable_lockset.access(address, self.thread_lockset.get_lockset(thread_id)) and self.variable_threadset.add_thread(address, thread_id) > 1:
            for info_line in ql.mem.get_formatted_mapinfo():
                self.default_debug(info_line, debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            raise InternalException(ql, "data race exists.\n" + hex(address))

    def write_hook(self, ql: Qiling, access: int, address: int, size: int, value: int, *context: Any):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        thread_id = ql.os.thread_management.cur_thread.id
        self.default_debug(f"{thread_id} write {hex(address)}, size {int(size)}, value {int(value)}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        if not self.variable_lockset.access(address, self.thread_lockset.get_lockset(thread_id)) and self.variable_threadset.add_thread(address, thread_id) > 1:
            for info_line in ql.mem.get_formatted_mapinfo():
                self.default_debug(info_line, debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            raise InternalException(ql, "data race exists.\n" + hex(address))

class LockVariables(SharedInterface):
    def __init__(self, ql: Qiling, thread_lockset, debug_level=QL_DEBUG_LEVEL.DEBUG_OFF):
        super().__init__(debug_level)
        self.__ql=ql
        self.__lock_thread = threading.Lock()
        self.__lock_variable_ptr = None
        self.thread_lockset = thread_lockset

        #
        self.__ql.os.set_api('pthread_mutex_lock', self.__on_mutex_lock_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('pthread_mutex_unlock', self.__on_mutex_unlock_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('pthread_mutex_unlock', self.__on_mutex_unlock_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('pthread_rwlock_rdlock', self.__on_rwlock_lock_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('pthread_rwlock_unlock', self.__on_rwlock_unlock_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('pthread_rwlock_unlock', self.__on_rwlock_unlock_exit, QL_INTERCEPT.EXIT)

    def __on_mutex_lock_enter(self, ql: Qiling):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        params = ql.os.resolve_fcall_params({'mutex_ptr': int})
        for key, value in params.items():
            self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        self.__lock_variable_ptr = params['mutex_ptr']
        thread_id = ql.os.thread_management.cur_thread.id
        self.thread_lockset.add_lock(tid=thread_id, lock=self.__lock_variable_ptr)

    def __on_mutex_unlock_enter(self, ql: Qiling):
        try:
            self.__lock_thread.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'mutex_ptr': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            self.__lock_variable_ptr = params['mutex_ptr']
        except Exception as e:
            self.__lock_thread.release()
            raise e

    def __on_mutex_unlock_exit(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            thread_id = ql.os.thread_management.cur_thread.id
            self.thread_lockset.remove_lock(tid=thread_id, lock=self.__lock_variable_ptr)
        finally:
            self.__lock_thread.release()

    def __on_rwlock_lock_enter(self, ql: Qiling):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        params = ql.os.resolve_fcall_params({'mutex_ptr': int})
        for key, value in params.items():
            self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        self.__lock_variable_ptr = params['mutex_ptr']
        thread_id = ql.os.thread_management.cur_thread.id
        self.thread_lockset.add_lock(tid=thread_id, lock=self.__lock_variable_ptr)

    def __on_rwlock_unlock_enter(self, ql: Qiling):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        self.__on_mutex_unlock_enter(ql)

    def __on_rwlock_unlock_exit(self, ql: Qiling):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        self.__on_mutex_unlock_exit(ql)


# Heap variables are recorded by hijacking the application interface
class HeapVariables(SharedInterface):
    def __init__(self, ql: Qiling, variable_lockset, variable_threadset, debug_level=QL_DEBUG_LEVEL.DEBUG_OFF) -> None:

        super().__init__(debug_level)
        self.__ql = ql

        # Thread-safe locks
        self.__lock_alloc = threading.Lock()
        self.__variable_hookset = VariableHookSet(debug_level)

        self.variable_lockset = variable_lockset
        self.variable_threadset = variable_threadset

        # Used to record parameters
        self.__user_size = None

        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        # Every enter and exit is locked to keep the thread safe
        self.__ql.os.set_api('malloc', self.__on_malloc_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('malloc', self.__on_malloc_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('calloc', self.__on_calloc_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('calloc', self.__on_calloc_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('realloc', self.__on_realloc_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('realloc', self.__on_realloc_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('free', self.__on_free_enter, QL_INTERCEPT.ENTER)

        # _Znwj is new in libc, this is crazy
        self.__ql.os.set_api('_Znwj', self.__on_new_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('_Znwj', self.__on_new_exit, QL_INTERCEPT.EXIT)

        # _Znaj is new[] in libc
        self.__ql.os.set_api('_Znaj', self.__on_new_array_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api('_Znaj', self.__on_new_array_exit, QL_INTERCEPT.EXIT)

        # _ZdlPvj is delete in libc
        self.__ql.os.set_api('_ZdlPvj', self.__on_delete_enter, QL_INTERCEPT.ENTER)

        # _ZdaPv is delete[] in libc
        self.__ql.os.set_api('_ZdaPv', self.__on_delete_array_enter, QL_INTERCEPT.ENTER)


    def __on_malloc_enter(self, ql: Qiling):
        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            # Record the parameters
            self.__user_size = params['size']
        except Exception as e:
            self.__lock_alloc.release()
            raise e

    def __on_malloc_exit(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            address = ql.os.fcall.cc.getReturnValue()
            self.default_debug("address: " + str(hex(address)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            begin_address = address
            end_address = address + self.__user_size - 1
            read_hook = ql.hook_mem_read(self.read_hook, begin=begin_address, end=end_address)
            write_hook = ql.hook_mem_write(self.write_hook, begin=begin_address, end=end_address)
            self.__variable_hookset.add_variable(address,[read_hook,write_hook])

        finally:
            self.__lock_alloc.release()

    def __on_calloc_enter(self, ql: Qiling):
        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'nitems': int, 'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            # Record the parameters
            self.__user_size = params['size'] * params['nitems']
        except Exception as e:
            self.__lock_alloc.release()
            raise e

    def __on_calloc_exit(self, ql: Qiling):
        self.__on_malloc_exit(ql)

    def __on_realloc_enter(self, ql: Qiling):

        try:
            self.__lock_alloc.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'address': int, 'size': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            address = params['address']
            self.__variable_hookset.remove_variable(address, ql)
            # Record the parameters
            self.__user_size = params['size']
        except Exception as e:
            self.__lock_alloc.release()
            raise e

    def __on_realloc_exit(self, ql: Qiling):
        self.__on_malloc_exit(ql)

    def __on_new_enter(self, ql: Qiling):
        self.__on_malloc_enter(ql)

    def __on_new_exit(self, ql: Qiling):
        self.__on_malloc_exit(ql)

    def __on_new_array_enter(self, ql: Qiling):
        self.__on_malloc_enter(ql)

    def __on_new_array_exit(self, ql: Qiling):
        self.__on_malloc_exit(ql)

    def __on_free_enter(self, ql: Qiling):

        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        params = ql.os.resolve_fcall_params({'address': int})
        for key, value in params.items():
            self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        # Record the parameters
        address = params['address']
        self.__variable_hookset.remove_variable(address,ql)
        del self.variable_lockset.map[address]
        del self.variable_threadset.map[address]

    def __on_delete_enter(self, ql: Qiling):
        self.__on_free_enter(ql)

    def __on_delete_array_enter(self, ql: Qiling):
        self.__on_free_enter(ql)


class ThreadSanitizer(SharedInterface):
    def __init__(self, ql: Qiling, detect_types=QL_DETECT_TYPES.ENABLE_THREAD_ALL, exception_class=DefaultException, debug_level=QL_DEBUG_LEVEL.DEBUG_OFF):

        super().__init__(debug_level)
        self.__ql = ql
        self.__exception_class = exception_class(debug_level)
        self.__detect_types = detect_types

        LockVariables(ql, self.thread_lockset, debug_level)
        HeapVariables(ql, self.variable_lockset, self.variable_threadset, debug_level)

        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

        for info_line in ql.mem.get_formatted_mapinfo():
            self.default_debug(info_line, debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        for info_line in ql.mem.get_mapinfo():

            # We monitor the data on the stack to avoid it being executed
            if "[stack]" == info_line[3]:
                # stack
                begin_address = info_line[0]
                end_address = info_line[1]
                self.default_debug(f"begin = {hex(begin_address)}, end = {hex(end_address)}",
                                     debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
                read_hook = ql.hook_mem_read(self.read_hook, begin=begin_address, end=end_address)
                write_hook = ql.hook_mem_write(self.write_hook, begin=begin_address, end=end_address)
                #self.__variable_hookset.add_variable(address,[read_hook,write_hook])

            if "rw-" == info_line[2] and ql.argv[0].split("/")[-1] == info_line[4].split("/")[-1]:
                # global variable
                begin_address = info_line[0]
                end_address = info_line[1]
                self.default_debug(f"begin = {hex(begin_address)}, end = {hex(end_address)}", debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
                read_hook = ql.hook_mem_read(self.read_hook, begin=begin_address, end=end_address)
                write_hook = ql.hook_mem_write(self.write_hook, begin=begin_address, end=end_address)
                #self.__variable_hookset.add_variable(address,[read_hook,write_hook])
