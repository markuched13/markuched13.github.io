### Controller HackTheBox Apocalypse21

### Binary Exploitation

### Basic File Checks

```
└─$ file controller
controller: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e5746004163bf77994992a4c4e3c04565a7ad5d6, not stripped
                                                                                                                                                                 
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/controller]
└─$ checksec controller
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/controller/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We're working with a x64 binary which is dynamically linked and not stripped

Looking at the protections we see that it has just `FULL RELRO` making GOT overwrite impossible and `NX ENABLED` making ret2shellcode not possible

I'll run the binary to know what it does

```
└─$ ./controller           

👾 Control Room 👾

Insert the amount of 2 different types of recources: 1 1
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 1
1 + 1 = 2
Insert the amount of 2 different types of recources: 2 10
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
2 * 10 = 20
Insert the amount of 2 different types of recources: ^C
```

We see that its some sort of calculator 

Using ghidra i'll decompile the binary

Here' sh
