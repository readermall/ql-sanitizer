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
from sanitizers.thread_sanitizer import DefaultException
from sanitizers.thread_sanitizer import ThreadSanitizer


# The user can customize an exception handling class, but needs to inherit from DefaultException
class MyException(DefaultException):
    def uaf_handler(self, ql, access, addr, size, value):
        super().uaf_handler(ql, access, addr, size, value)

def mem_read(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
    for info_line in ql.mem.get_formatted_mapinfo():
        print(info_line)
    #ql.log.debug(f'intercepted a memory read from {address:#x}')


if __name__ == "__main__":
    
    # Supported Platforms
    platforms = ["aarch64", "arm",
                "mips", "mips64", "mips64el", "mipsel",
                "powerpc", "powerpc64", "powerpc64le",
                "riscv64",
                "i686", "x86_64"]

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help='input bin')
    parser.add_argument('-p', '--platform', help='detect platform, all means all platforms, guessed based on input is default')
    
    # The user must provide the files to be detected
    args = parser.parse_args()
    if not args.input:
        raise RuntimeError("-i/--input are required!")

    rootfs = ["/usr/"]

    # We guess the platform based on the value of the input
    filename = re.split("/|-|_| ", args.input)
    for p in platforms:
        for word in filename:
            if p == word:
                # host rootfs in /usr/, other in /usr/{platform}-linux-*
                rootfs = glob.glob("/usr/" + p + "-linux-*")
                break

    ql = Qiling([args.input], rootfs[0], multithread=True, verbose=QL_VERBOSE.DEBUG)
    
    #for info_line in ql.mem.get_formatted_mapinfo():
    #    print(info_line)

    #ql.hook_mem_read(mem_read, begin=0x5655c1a0, end=0x5655c1a4)
    #ql.hook_mem_read(mem_read, begin=0x90244348, end=0x9024434c)
    #ql.hook_mem_read(mem_read, begin=0x90275348, end=0x9027534c)
    ThreadSanitizer(ql, detect_types=QL_DETECT_TYPES.ENABLE_THREAD_ALL, debug_level=QL_DEBUG_LEVEL.DEBUG_ALL)
    ql.run()
