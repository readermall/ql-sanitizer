#!/usr/bin/env python3

#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# 2023-12-19
# Author: readermall and liuyi
#
#

import os
import glob
import subprocess
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-a', '--archs', help='archs',nargs="+")
parser.add_argument('-m', '--modules', help='modules',nargs="+")
args = parser.parse_args()

#print(args.archs)
#print(args.modules)

src_path = './src/'
compiler_path = "/usr/bin/"

# 获取当前目录下的所有 .c 和 .cpp 文件
source_files = [f for f in os.listdir(src_path) if f.endswith('.c') or f.endswith('.cpp')]
platform = ["aarch64", "arm",
            "mips", "mips64", "mips64el", "mipsel",
            "powerpc", "powerpc64", "powerpc64le",
            "riscv64",
            "i686", "x86_64"]
platform = set(platform).intersection(set(args.archs)) if args.archs else platform

# 创建一个名为 "bin-{platform}" 的子目录，用于存放生成的可执行文件
for p in platform:
    if not os.path.isdir('bin-' + p):
        os.mkdir('bin-' + p)

for p in platform:
    for source_file in source_files:
        if args.modules and all(x not in source_file for x in args.modules): continue
        # 获取文件名和扩展名
        name, ext = os.path.splitext(source_file)

        # 设置编译器命令和选项
        if ext == '.c':
            compiler_pattern = p + '-linux-*-gcc'
        elif ext == '.cpp':
            compiler_pattern = p + '-linux-*-g++'
        #print(compiler_pattern)
        compiler = glob.glob(compiler_path + compiler_pattern, recursive = True)
        options = ['-O0', '-o', os.path.join('bin-' + p, name)]

        # 构建编译命令并执行
        command = [compiler[0]] + options + [src_path + source_file]
        if "thread" in args.modules:
            command.append("-lpthread")
        #print(command)
        subprocess.run(command, check = True)
