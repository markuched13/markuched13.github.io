### DearQA TryHackMe

### Difficulty = Easy

### IP Address = 10.10.175.23 

### Basic File Checks

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/DearQA]
└─$ file DearQA.DearQA 
DearQA.DearQA: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8dae71dcf7b3fe612fe9f7a4d0fa068ff3fc93bd, not stripped
                                                                                                                                                                                                                  
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/DearQA]
└─$ checksec DearQA.DearQA       
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/B2B/THM/DearQA/DearQA.DearQA'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

We're working with a x64 binary and no protection is enabled on the binary

I'll run it to get an overview of what it does

```
