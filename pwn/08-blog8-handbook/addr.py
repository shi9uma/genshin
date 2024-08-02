# -*- coding: utf-8 -*-

from pwn import *

funclist = [
    ['system', 'plt'], 
    ['system', 'got'], 
    ['puts', 'plt'], 
    ['puts', 'got'], 
    ['write', 'plt'], 
    ['write', 'got'], 
    ['binsh_addr', 'string'], 
    ['ret_addr', 'asm'],
    ]

def getFile():
    try:
        elfname = sys.argv[1]
    except BaseException:
        banner = '''
    输入 elfname
    example: python addr.py libc.so.6
        '''
        print(banner)
        exit()
    return elfname

def check(elfname):    
    elf = ELF(elfname)
    for func in funclist:
        funcion(elf, func[0], func[1]).start()
    
class funcion():
    def __init__(self, elf, name, mode):
        self.elf = elf
        self.name = name
        self.mode = mode
        
    def start(self):
    
        def plt(self):
            plt = None
            try:
                plt = hex(self.elf.plt[self.name])
            except BaseException:
                pass
            print(self.name + '_plt =', plt)
                
        def got(self):
            got = None
            try:
                got = hex(self.elf.got[self.name])
            except BaseException:
                pass
            print(self.name + '_got =', got)

        def string(self):
            str_bin_sh = None
            try:
                str_bin_sh = hex(next(self.elf.search(b"/bin/sh")))
            except BaseException:
                pass
            print(self.name + ' =', str_bin_sh)
                
        def myAsm(self):
            ret_addr = None
            try:
                ret_addr = hex(next(self.elf.search(b'\xc3')))
            except BaseException:
                pass
            print(self.name + ' =', ret_addr)
        
        case = {
            'plt': plt,
            'got': got,
            'string': string,
            'asm': myAsm
        }

        if self.mode in case.keys():
            case.get(self.mode)(self)
    
if __name__ == "__main__":
    elfname = getFile()
    try:
        check(elfname)
    except Exception as e:
        print(e)
    