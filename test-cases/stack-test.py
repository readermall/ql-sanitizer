#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import argparse
import sys
import threading
import glob
import re

sys.path.append("../qiling")
sys.path.append("..")

from qiling import Qiling
from sanitizers.stack_sanitizer import QL_DETECT_TYPES, QL_DEBUG_LEVEL
from sanitizers.stack_sanitizer import DefaultException
from sanitizers.stack_sanitizer import StackSanitizer


def pop_canary(ql: Qiling) -> None:
    print("hello")


if __name__ == "__main__":
    platforms = ["aarch64", "arm",
                "mips", "mips64", "mips64el", "mipsel",
                "powerpc", "powerpc64", "powerpc64le",
                "riscv64",
                "i686", "x86_64"]
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input',help='input bin')

    args = parser.parse_args()
    if not args.input:
        raise RuntimeError("-i/--input is required!")

    rootfs = ["/usr/"]
 
    # We guess the platform based on the value of the input
    filename = re.split("/|-|_| ", args.input)
    for p in platforms:
        for word in filename:
            if p == word:
                # host rootfs in /usr/, other in /usr/{platform}-linux-*
                rootfs = glob.glob("/usr/" + p + "-linux-*")
                break
 
    print(rootfs[0])
    ql = Qiling([args.input], rootfs[0])
    StackSanitizer(ql, detect_types=QL_DETECT_TYPES.ENABLE_STACK_CANARY_WRITE, debug_level=QL_DEBUG_LEVEL.DEBUG_EVERY)
    ql.run()
