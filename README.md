# ql-sanitizer

Sanitizer based on the Qiling framework

Currently, heap memory errors, stack memory errors, and thread error detection are supported

1. heap memory errors

buffer overflow/underflow
out-of-bounds
use-after-free
bad/double free
method not match
uninitialized memory read

2. stack memory errors

on-stack code execution
canary word being write

3. thread error

data race

By default, an exception is thrown when the above code error is detected
The User can customize their own exception handling function by inheriting DefaultException
The user can adjust the log to be output by adjusting the print level parameter

Thanks to qiling-framework for this project

## License

This project is released and distributed under free software license GPLv2 and later version.

## Installation

1. Clone the repository

$ git clone https://github.com/readermall/ql-sanitizer

2. Clone the qiling subrepository

$ cd ql-sanitizer
$ git submodule update --init --recursive

3. Install the dependencies of the Qiling framework

please refer to the specific installation method from https://github.com/qilingframework/qiling or https://qiling.io/

## Examples

1. Detect heap overflow

```python
$ cd test-cases
$ python3 heap-test.py --input ./bin-i686/heap-malloc-ob
```

results
```
[=]     brk(inp = 0x0) = 0x5655c000
[=]     arch_prctl(code = 0x3001, addr = 0x7ff3ce58) = -0x1 (EPERM)
[=]     uname(buf = 0x7ff3ca8a) = 0x0
[=]     access(path = 0x47dabf1, mode = 0x0) = -0x1 (EPERM)
[=]     access(path = 0x47dc574, mode = 0x4) = -0x1 (EPERM)
[=]     openat(fd = 0xffffff9c, path = 0x47dafac, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = -0x1 (EPERM)
[=]     stat64(path = 0x7ff3c2b0, buf_ptr = 0x7ff3c330) = -0x2 (ENOENT)
[=]     openat(fd = 0xffffff9c, path = 0x7ff3c2b0, flags = 0x88000, mode = 0x0) = 0x3
[=]     read(fd = 0x3, buf = 0x7ff3c400, length = 0x200) = 0x200
[=]     pread64(fd = 0x3, buf = 0x7ff3c1e0, length = 0x60, offt = 0x1d4) = 0x60
[=]     fstat64(fd = 0x3, buf_ptr = 0x7ff3c330) = 0x0
[=]     mmap2(addr = 0x0, length = 0x2000, prot = 0x3, flags = 0x22, fd = 0xffffffff, pgoffset = 0x0) = 0x90000000
[=]     pread64(fd = 0x3, buf = 0x7ff3c0b0, length = 0x60, offt = 0x1d4) = 0x60
[=]     mmap2(addr = 0x0, length = 0x1ee6c0, prot = 0x1, flags = 0x802, fd = 0x3, pgoffset = 0x0) = 0x90002000
[=]     mprotect(start = 0x9001b000, mlen = 0x1d0000, prot = 0x0) = 0x0
[=]     mmap2(addr = 0x9001b000, length = 0x15b000, prot = 0x5, flags = 0x812, fd = 0x3, pgoffset = 0x19) = 0x9001b000
[=]     mmap2(addr = 0x90176000, length = 0x74000, prot = 0x1, flags = 0x812, fd = 0x3, pgoffset = 0x174) = 0x90176000
[=]     mmap2(addr = 0x901eb000, length = 0x3000, prot = 0x3, flags = 0x812, fd = 0x3, pgoffset = 0x1e8) = 0x901eb000
[=]     mmap2(addr = 0x901ee000, length = 0x26c0, prot = 0x3, flags = 0x32, fd = 0xffffffff, pgoffset = 0x0) = 0x901ee000
[=]     close(fd = 0x3) = 0x0
[=]     set_thread_area(u_info_addr = 0x7ff3cc10) = 0x0
[=]     mprotect(start = 0x901eb000, mlen = 0x2000, prot = 0x1) = 0x0
[=]     mprotect(start = 0x56558000, mlen = 0x1000, prot = 0x1) = 0x0
[=]     mprotect(start = 0x47e5000, mlen = 0x1000, prot = 0x1) = 0x0
[#]     __on_malloc_enter in...
[#]     params : size = 0x400
[#]     resize: 0x408
[=]     brk(inp = 0x0) = 0x5655c000
[=]     brk(inp = 0x5657d000) = 0x5657d000
[=]     brk(inp = 0x5657e000) = 0x5657e000
[#]     __on_malloc_exit in...
[#]     __on_alloc_exit in...
[#]     real address: 0x5655c1a0
[#]     red area1 start_addr: 0x5655c1a0
[#]     red area1 end_addr: 0x5655c1a3
[#]     user memory start_addr: 0x5655c1a4
[#]     user memory end_addr: 0x5655c5a3
[#]     red area2 start_addr: 0x5655c5a4
[#]     red area2 end_addr: 0x5655c5a7
[#]     address: 0x5655c1a4
[=]     fstat64(fd = 0x1, buf_ptr = 0x7ff3c7cc) = 0x0
malloc address = 5655c1a4
[=]     write(fd = 0x1, buf = 0x5655c5b0, count = 0x1a) = 0x1a
Traceback (most recent call last):
  File "heap-test.py", line 66, in <module>
    ql.run()
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core.py", line 595, in run
    self.os.run()
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/os/linux/linux.py", line 184, in run
    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core.py", line 775, in emu_start
    raise self.internal_exception
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks.py", line 127, in wrapper
    return callback(*args, **kwargs)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks.py", line 230, in _hook_mem_cb
    ret = hook.call(ql, access, addr, size, value)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks_types.py", line 25, in call
    return self.callback(ql, *args)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../sanitizers/sanitizer_utils.py", line 70, in bo_handler
    raise InternalException(ql, "buffer overflow/underflow is detected.\n" + "address : " + hex(address) + ", write value : " + hex(value))
sanitizers.sanitizer_utils.InternalException: buffer overflow/underflow is detected.
address : 0x5655c1a3, write value : 0x1:
  [CONTEXT]:
<qiling.arch.register.QlRegisterManager object at 0x7f10f0b1cd90>
```

2. Detect stack canary

```
$ cd test-cases
$ python3 stack-test.py --input ./bin-i686/stack-test.py
```

results
```
...
[#]     push depth : 0x3
[#]             0x00000056556264 : call                     0x56556090
[#]             0x00000056556090 : endbr32
[#]             post push lr : 0x7ff3cccc ==> 0x56556269
[#]     push depth : 0x4
[#]             hook area : 0x7ff3cccc
Traceback (most recent call last):
  File "stack-test.py", line 53, in <module>
    ql.run()
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core.py", line 595, in run
    self.os.run()
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/os/linux/linux.py", line 184, in run
    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core.py", line 775, in emu_start
    raise self.internal_exception
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks.py", line 127, in wrapper
    return callback(*args, **kwargs)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks.py", line 230, in _hook_mem_cb
    ret = hook.call(ql, access, addr, size, value)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks_types.py", line 25, in call
    return self.callback(ql, *args)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../sanitizers/sanitizer_utils.py", line 124, in stack_write_handler
    raise InternalException(ql, "canary word being write is detected.\n" + "stack address : " + hex(address) + ", write value : " + hex(value))
sanitizers.sanitizer_utils.InternalException: canary word being write is detected.
stack address : 0x7ff3cd06, write value : 0x3232323232323232:
  [CONTEXT]:
<qiling.arch.register.QlRegisterManager object at 0x7ff692d87c10>
```

3. Detect data race

```
$ cd test-cases
$ python3 thread-test.py --input ./bin-i686/thread-data-race-heap
```

results
```
[+] [Thread 2001]       [Thread Manager] Stop the world.
Traceback (most recent call last):
  File "src/gevent/greenlet.py", line 908, in gevent._gevent_cgreenlet.Greenlet.run
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/os/linux/thread.py", line 242, in _run
    self.ql.emu_start(start_address, self.exit_point, count=31337)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core.py", line 775, in emu_start
    raise self.internal_exception
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks.py", line 127, in wrapper
    return callback(*args, **kwargs)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks.py", line 230, in _hook_mem_cb
    ret = hook.call(ql, access, addr, size, value)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../qiling/qiling/core_hooks_types.py", line 25, in call
    return self.callback(ql, *args)
  File "/home/ubuntu/qiling2/ql-sanitizer/ql-sanitizer/test-cases/../sanitizers/thread_sanitizer.py", line 133, in read_hook
    raise InternalException(ql, "data race exists.\n" + hex(address))
sanitizers.sanitizer_utils.InternalException: data race exists.
0x56558f14:
  [CONTEXT]:
<qiling.arch.register.QlRegisterManager object at 0x7f3566f95520>
```

## Contact

Contact us at email ireading@foxmail.com, or via QQ: 936571349
contribution ireading, liuyi
