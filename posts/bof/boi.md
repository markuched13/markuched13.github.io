### Buffer Overflow Practice

### Source: CSAW18

### Basic File Check

```
┌──(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ file boi     
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
                                                                                                                                                                                                                                                                                                                                                                                                                                    
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ checksec boi     
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

We're working with a x64 binary which is dynamically linked and non stripped 

It has canary & NX enabled as its protection

Lets run it to see what it does

```
