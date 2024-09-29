# -*- coding: utf-8 -*-

import os
import sys

from qiling import Qiling
from qiling.const import QL_VERBOSE

workdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../')
elf_path = os.path.join(workdir, 'archive/01-qilinglab-v86_64')
print(workdir, elf_path)
argv = ''





############################################################################################################
from qiling import Qiling

qemu_argv = ['elf_path', 'argv1', 'argv2']
qemu_rootfs_path = './a-rootfs-x86_64'
qemu_env = ['HOME=/', 'PATH=/sbin:/bin']

ql = Qiling(qemu_argv, qemu_rootfs_path, qemu_env)


# runtime hook
buf = b'Hello, World!\n'
ql.os.fd[write_fd].write(buf)

# function hook
def custom_puts(ql):
    pass
def custom_syscall_read(ql):
    pass

ql.set_api('puts', custom_puts)
ql.set_syscall('read', custom_syscall_read)

# register operation
ql.reg.read('rax')  # 读 rax
ql.reg.write('rax', 0x1234)  # 写 rax

# memory operation
ql.mem.map(0x1000, 0x1000)  # 操作内存前映射内存
ql.mem.write(0x1000, b'Hello, World!\n\x00')  # 写内存
ql.mem.search(0x1000, 0x2000, b'World')  # 搜索内存

# filesystem operation
from qiling.os.mapper import QlFsMappedObject
class fake_urandom(QlFsMappedObject):
    def read(self, size):
        return b'\x00'
    def fstat(self):
        return {'st_size': 0}
ql.add_fs_mapper('/dev/urandom')

ql.run()