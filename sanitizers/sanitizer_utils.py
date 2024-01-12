import sys
from enum import IntEnum

sys.path.append("../..")

from qiling import Qiling

class QL_DEBUG_LEVEL(IntEnum):
    DEBUG_OFF = 0
    DEBUG_TRACE = 1
    DEBUG_INFO = 2
    DEBUG_EVERY = 3
    DEBUG_ALL = 4


class QL_DETECT_TYPES(IntEnum):
    ENABLE_HEAP_OOB = 1
    ENABLE_HEAP_OB = 2
    ENABLE_HEAP_UAF = 4
    ENABLE_HEAP_DF = 8
    ENABLE_HEAP_UINIT = 16
    ENABLE_HEAP_MISMATCH = 32
    ENABLE_HEAP_ALL = 63

    ENABLE_STACK_NX = 64
    ENABLE_STACK_CANARY_WRITE = 128
    ENABLE_STACK_ALL = 192

    ENABLE_THREAD_DR = 256
    ENABLE_THREAD_DL = 512
    ENABLE_THREAD_ALL = 768

class InternalException(Exception):
    def __init__(self, ql: Qiling, msg: str) -> None:
        super().__init__(msg)
        self.ql = ql
        self.context = str(ql.arch.regs) if ql else "None"
        self.msg = msg

    def __str__(self):
        return f"{self.msg}: \n  [CONTEXT]: \n{self.context}"


class DebugUtil:
    def __init__(self, debug_level):
        self.__debug_level = debug_level

    def default_debug(self, *params: any, debug_level: QL_DEBUG_LEVEL, end="\n"):
        if self.__debug_level > debug_level:
            for each in params:
                print("\033[0;33;40m[#]\033[0m\t" + each, end=end)


#
# The default exception handling class, which users can inherit and customize their own exception handling
# 
class DefaultException(DebugUtil):

    def __init__(self, debug_level):
        super().__init__(debug_level)
        self.is_raise = True

    def bo_handler(self, ql, access, address, size, value):
        """
        Called when a buffer overflow/underflow is detected.
        """
        if self.is_raise == False:
            self.default_debug("buffer overflow/underflow is detected.\n" + "address : " + hex(address) + ", write value : " + hex(value))
        else:
            raise InternalException(ql, "buffer overflow/underflow is detected.\n" + "address : " + hex(address) + ", write value : " + hex(value))

    def oob_handler(self, ql, access, address, size, value):
        """
        Called when an out-of-bounds element is accessed.
        """
        if self.is_raise == False:
            self.default_debug("out-of-bounds element is accessed.\n" + "address : " + hex(address))
        else:
            raise InternalException(ql, "out-of-bounds element is accessed.\n" + "address : " + hex(address))

    def uaf_handler(self, ql, access, address, size, value):
        """
        Called when a use-after-free is detected.
        """
        if self.is_raise == False:
            self.default_debug("use-after-free is detected.\n" + "address : " + hex(address))
        else:
            raise InternalException(ql, "use-after-free is detected.\n" + "address : " + hex(address))

    def bad_free_handler(self, ql, address):
        """
        Called when a bad/double free is detected.
        """
        if self.is_raise == False:
            self.default_debug("bad/double free is detected.\n" + "address : " + hex(address))
        else:
            raise InternalException(ql, "bad/double free is detected.\n" + "address : " + hex(address))

    def bad_free_method_hander(self, ql, alloc_method, free_method):
        """
        Called when a release method not match is detected.
        """
        if self.is_raise == False:
            self.default_debug("release method not match is detected.\n" + "alloc method is : " + alloc_method + ", but release method is : " + free_method)
        else:
            raise InternalException(ql, "release method not match is detected.\n" + "alloc method is : " + alloc_method + ", but release method is : " + free_method)

    def stack_exec_handler(self, ql: Qiling):
        """
        Called when on-stack code execution is detected.
        """
        if self.is_raise == False:
            self.default_debug("canary exec is detected.")
        else:
            raise InternalException(ql, "canary exec is detected.")

    def stack_write_handler(self, ql: Qiling, access: int, address: int, size: int, value: int):
        """
        Called when canary word being write is detected.
        """
        if self.is_raise == False:
            self.default_debug("canary word being write is detected.\n" + "stack address : " + hex(address) + ", write value : " + hex(value))
        else:
            raise InternalException(ql, "canary word being write is detected.\n" + "stack address : " + hex(address) + ", write value : " + hex(value))
