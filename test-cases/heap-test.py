import argparse
import sys
import threading
import glob
import re

sys.path.append("../qiling")
sys.path.append("..")

from qiling import Qiling
from sanitizers.heap_sanitizer import QL_DETECT_TYPES, QL_DEBUG_LEVEL
from sanitizers.heap_sanitizer import DefaultException
from sanitizers.heap_sanitizer import HeapSanitizer


# The user can customize an exception handling class, but needs to inherit from DefaultException
class MyException(DefaultException):
    def uaf_handler(self, ql, access, addr, size, value):
        super().uaf_handler(ql, access, addr, size, value)

if __name__ == "__main__":
    
    # Supported Platforms
    platforms = ["aarch64", "arm",
                "mips", "mips64", "mips64el", "mipsel",
                "powerpc", "powerpc64", "powerpc64le",
                "riscv64",
                "i686", "x86_64"]

    # Supported Detect Types
    types = {"df" : QL_DETECT_TYPES.ENABLE_HEAP_DF, "uaf" : QL_DETECT_TYPES.ENABLE_HEAP_UAF, \
            "ob" : QL_DETECT_TYPES.ENABLE_HEAP_OB, "oob" : QL_DETECT_TYPES.ENABLE_HEAP_OOB, \
            "uinit" : QL_DETECT_TYPES.ENABLE_HEAP_UINIT, "mismatch" : QL_DETECT_TYPES.ENABLE_HEAP_MISMATCH, \
            "all" : QL_DETECT_TYPES.ENABLE_HEAP_ALL}

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help='input bin')
    parser.add_argument('-t', '--type', help='detect type, all means all types, all is default')
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

    detect_type = QL_DETECT_TYPES.ENABLE_HEAP_ALL

    for t in types:
        if t == args.type:
            detect_type = t.value
            break

    ql = Qiling([args.input], rootfs[0])
    HeapSanitizer(ql, detect_types=detect_type, debug_level=QL_DEBUG_LEVEL.DEBUG_ALL)
    ql.run()
