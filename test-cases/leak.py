import argparse
import sys
import threading
import glob
import re

sys.path.append("../qiling")
sys.path.append("..")

from qiling import Qiling
from sanitizers.thread_sanitizer import QL_DEBUG_LEVEL, QL_DETECT_TYPES
from sanitizers.leak_sanitizer import MemSanitizer
from sanitizers.leak_sanitizer import DefaultException

# The user can customize an exception handling class, but needs to inherit from DefaultException
class MyException(DefaultException):
    def uaf_handler(self, ql, access, addr, size, value):
        super().uaf_handler(ql, access, addr, size, value)

if __name__ == "__main__":
    

    ql = Qiling([r"./bin-x86_64/mem-leak"], r"../qiling/examples/rootfs/x8664_linux")
    MemSanitizer(ql, debug_level=QL_DEBUG_LEVEL.DEBUG_ALL)
    ql.run()
