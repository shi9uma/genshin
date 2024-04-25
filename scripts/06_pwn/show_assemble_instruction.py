# -*- coding: utf-8 -*-

from keystone import *

def assemble_instruction(instruction):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(instruction)
    return ' '.join(format(x, '02x') for x in encoding)

# 使用示例
instruction = str(input())
encoded_bytes = assemble_instruction(instruction)
print(f"Instruction: {instruction}\nEncoded Bytes: {encoded_bytes}")
