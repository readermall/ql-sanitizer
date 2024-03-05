import argparse
import sys
import threading
import glob
import re



sys.path.append("../qiling")
sys.path.append("..")

from qiling import Qiling
from qiling.const import *
from sanitizers.thread_sanitizer import QL_DEBUG_LEVEL, QL_DETECT_TYPES
from sanitizers.deadlock_sanitizer import deadlock_sanitizer,tarjan


# The user can customize an exception handling class, but needs to inherit from DefaultException
# class MyException(DefaultException):
#     def uaf_handler(self, ql, access, addr, size, value):
#         super().uaf_handler(ql, access, addr, size, value)

if __name__ == "__main__":
    
    # graph={}
    # graph[2001]=[]
    # graph[2001].append(2002)
    # graph[2002]=[]
    # graph[2002].append(2001)

    # t=tarjan(graph)
    # t.scan()
    ql = Qiling([r"./bin-x86_64/lock"], r"../qiling/examples/rootfs/x8664_linux",multithread=True)#,verbose=QL_VERBOSE.DEBUG
    deadlock_sanitizer(ql,debug_level=QL_DEBUG_LEVEL.DEBUG_ALL)#debug_level=QL_DEBUG_LEVEL.DEBUG_ALL
    ql.run()
