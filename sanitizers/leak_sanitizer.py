
from .sanitizer_utils import *
import threading




from qiling.const import QL_INTERCEPT, QL_CALL_BLOCK, QL_VERBOSE, QL_ARCH
from qiling.os.const import *
from enum import Enum, Flag, IntEnum
from bitarray import bitarray
from capstone import Cs


class QL_DEBUG_LEVEL(IntEnum):
    DEBUG_OFF = 0
    DEBUG_TRACE = 1
    DEBUG_INFO = 2
    DEBUG_EVERY = 3
    DEBUG_ALL = 4

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

   

class MemManage:
    def __init__(self) :
        self.__mem = []

    
    def add(self,address):
        self.__mem.append(str(hex(address)))

    def remove(self,address):
        self.__mem.remove(str(hex(address)))   

    def mems(self):
        return self.__mem
    

#
# Heap memory sanitizer to detect various heap memory usage errors
#
class MemSanitizer(DebugUtil):
    def __init__(self, ql:Qiling, debug_level):
        super().__init__(debug_level)
        self.__ql = ql
        # for info_line in ql.mem.get_formatted_mapinfo():
        #     self.default_debug(info_line, debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

        self.__mem_mange = MemManage()
        # Thread-safe locks
        # self.__lock_alloc = threading.Lock()
        # self.__lock_free = threading.Lock()
        # if ql.arch.type in [QL_ARCH.ARM64]:
        #     self.__ql.os.set_api('malloc', self.__on_malloc_enter, QL_INTERCEPT.ENTER)
        self.__ql.os.set_api("malloc", self.__on_malloc_exit, QL_INTERCEPT.EXIT)
        
        self.__ql.os.set_api('free', self.__on_free_enter, QL_INTERCEPT.ENTER)
        #self.__ql.os.set_api('free', self.__on_free_exit, QL_INTERCEPT.EXIT)

        self.__ql.os.set_api('__libc_start_main', self.__on___libc_start_main_enter, QL_INTERCEPT.ENTER)
        #self.__ql.os.set_api('__libc_start_main', self.__ret_hook, QL_INTERCEPT.EXIT)
    
    
    def __on_alloc_exit(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            real_address = ql.os.fcall.cc.getReturnValue()
            self.default_debug("real address: " + str(hex(real_address)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)
            self.__mem_mange.add(real_address)
        except Exception as e:
            raise e 
    
    def __on_malloc_exit(self, ql: Qiling):
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        return self.__on_alloc_exit(ql)
    
    
    #
    def __on_release_enter(self, ql: Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)

            params = ql.os.resolve_fcall_params({'address': int})
            for key, value in params.items():
                self.default_debug("params : " + key + " = " + str(hex(value)), debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)

            address = params['address']
            self.__mem_mange.remove(address)
        except Exception as e:
            raise e


        
    def __on_free_enter(self, ql: Qiling):
       
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        return self.__on_release_enter(ql)
    
   

    def __on___libc_start_main_enter(self,ql:Qiling):
        
        self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
        
        params = ql.os.resolve_fcall_params({'main': int})
        address=params['main']
        
        ql.hook_address(self.__ret_main__hook, address)

        #ql.hook_address(self.__ret_main__hook, address)
        
    
    
    def __ret_main__hook(self, ql:Qiling):
        if ql.arch.type in [QL_ARCH.MIPS]:
            ret_address = ql.arch.regs.read("RA")
        elif ql.arch.type in [QL_ARCH.ARM,QL_ARCH.ARM64]:
            ret_address=ql.arch.regs.read("LR")
        elif ql.arch.type in [QL_ARCH.X86,QL_ARCH.X8664]:
            ret_address=ql.arch.stack_read(0)
        
        
        ql.hook_address(self.__ret_hook, ret_address)
        

    def __ret_hook(self, ql:Qiling):
        mems=self.__mem_mange.mems()
        if len(mems)==0:
            print("maybe no leak!")
        else:
            print("LEAK SUMMARY:")
            for mem in mems:
                self.default_debug(mem, debug_level=QL_DEBUG_LEVEL.DEBUG_INFO)