### Reverse Engineering

### Helithumper

### Basic file check 

First i'll check the file type

```
┌──(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ chmod +x helithumper             
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ file helithumper 
helithumper: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e4dbcb1281821db359d566c68fea7380aeb27378, for GNU/Linux 3.2.0, not stripped
```

Now i'll check the protections enabled

```
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ checksec helithumper                                    
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/02-beginner_re/helithumper'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```
 
 Now i'll run it to know what it does
 
 ```
 ┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ ./helithumper  
Welcome to the Salty Spitoon™, How tough are ya?
tough
Yeah right. Back to Weenie Hut Jr™ with ya
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ ./helithumper
Welcome to the Salty Spitoon™, How tough are ya?
lol
Yeah right. Back to Weenie Hut Jr™ with ya
```

Nothing much it just accepts an input and prints `Yeah right. Back to Weenie Hut Jr™ with ya`

Now i'll check out the binary using gdb

```
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ gdb -q ./helithumper
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from ./helithumper...
(No debugging symbols found in ./helithumper)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  strlen@plt
0x0000000000001050  __stack_chk_fail@plt
0x0000000000001060  calloc@plt
0x0000000000001070  __isoc99_scanf@plt
0x0000000000001080  __cxa_finalize@plt
0x0000000000001090  _start
0x00000000000010c0  deregister_tm_clones
0x00000000000010f0  register_tm_clones
0x0000000000001130  __do_global_dtors_aux
0x0000000000001170  frame_dummy
0x0000000000001175  main
0x00000000000011ea  validate
0x00000000000012d0  __libc_csu_init
0x0000000000001330  __libc_csu_fini
0x0000000000001334  _fini
gef➤ 
```

We have two functions that are of interest to us

Lets disassemble the validate function

```
gef➤  disass validate
Dump of assembler code for function validate:
   0x00000000000011ea <+0>:     push   rbp
   0x00000000000011eb <+1>:     mov    rbp,rsp
   0x00000000000011ee <+4>:     sub    rsp,0x60
   0x00000000000011f2 <+8>:     mov    QWORD PTR [rbp-0x58],rdi
   0x00000000000011f6 <+12>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000011ff <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001203 <+25>:    xor    eax,eax
   0x0000000000001205 <+27>:    mov    DWORD PTR [rbp-0x40],0x66
   0x000000000000120c <+34>:    mov    DWORD PTR [rbp-0x3c],0x6c
   0x0000000000001213 <+41>:    mov    DWORD PTR [rbp-0x38],0x61
   0x000000000000121a <+48>:    mov    DWORD PTR [rbp-0x34],0x67
   0x0000000000001221 <+55>:    mov    DWORD PTR [rbp-0x30],0x7b
   0x0000000000001228 <+62>:    mov    DWORD PTR [rbp-0x2c],0x48
   0x000000000000122f <+69>:    mov    DWORD PTR [rbp-0x28],0x75
   0x0000000000001236 <+76>:    mov    DWORD PTR [rbp-0x24],0x43
   0x000000000000123d <+83>:    mov    DWORD PTR [rbp-0x20],0x66
   0x0000000000001244 <+90>:    mov    DWORD PTR [rbp-0x1c],0x5f
   0x000000000000124b <+97>:    mov    DWORD PTR [rbp-0x18],0x6c
   0x0000000000001252 <+104>:   mov    DWORD PTR [rbp-0x14],0x41
   0x0000000000001259 <+111>:   mov    DWORD PTR [rbp-0x10],0x62
   0x0000000000001260 <+118>:   mov    DWORD PTR [rbp-0xc],0x7d
   0x0000000000001267 <+125>:   mov    rax,QWORD PTR [rbp-0x58]
   0x000000000000126b <+129>:   mov    rdi,rax
   0x000000000000126e <+132>:   call   0x1040 <strlen@plt>
   0x0000000000001273 <+137>:   mov    DWORD PTR [rbp-0x44],eax
   0x0000000000001276 <+140>:   mov    DWORD PTR [rbp-0x48],0x0
   0x000000000000127d <+147>:   jmp    0x12aa <validate+192>
   0x000000000000127f <+149>:   mov    eax,DWORD PTR [rbp-0x48]
   0x0000000000001282 <+152>:   movsxd rdx,eax
   0x0000000000001285 <+155>:   mov    rax,QWORD PTR [rbp-0x58]
   0x0000000000001289 <+159>:   add    rax,rdx
   0x000000000000128c <+162>:   movzx  eax,BYTE PTR [rax]
   0x000000000000128f <+165>:   movsx  edx,al
   0x0000000000001292 <+168>:   mov    eax,DWORD PTR [rbp-0x48]
   0x0000000000001295 <+171>:   cdqe   
   0x0000000000001297 <+173>:   mov    eax,DWORD PTR [rbp+rax*4-0x40]
   0x000000000000129b <+177>:   cmp    edx,eax
   0x000000000000129d <+179>:   je     0x12a6 <validate+188>
   0x000000000000129f <+181>:   mov    eax,0x0
   0x00000000000012a4 <+186>:   jmp    0x12b7 <validate+205>
   0x00000000000012a6 <+188>:   add    DWORD PTR [rbp-0x48],0x1
   0x00000000000012aa <+192>:   mov    eax,DWORD PTR [rbp-0x48]
   0x00000000000012ad <+195>:   cmp    eax,DWORD PTR [rbp-0x44]
   0x00000000000012b0 <+198>:   jl     0x127f <validate+149>
   0x00000000000012b2 <+200>:   mov    eax,0x1
   0x00000000000012b7 <+205>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000000012bb <+209>:   xor    rcx,QWORD PTR fs:0x28
   0x00000000000012c4 <+218>:   je     0x12cb <validate+225>
   0x00000000000012c6 <+220>:   call   0x1050 <__stack_chk_fail@plt>
   0x00000000000012cb <+225>:   leave  
   0x00000000000012cc <+226>:   ret    
End of assembler dump.
gef➤
```

Cool we see some hex values are being stored in a variable

Lets decode using python

Here's the script

```
┌──(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ cat helithumper.py 
encode = [0x66, 0x6c, 0x61, 0x67, 0x7b, 0x48, 0x75, 0x43, 0x66, 0x5f, 0x6c, 0x41, 0x62, 0x7d]
decoded = ""

for i in encode:
        decoded += chr(i)

print(decoded)
```

Lets run it 

```
┌──(mark㉿haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ python3 helithumper.py
flag{HuCf_lAb}
```

Now we have the flag

Flag: `flag{HuCf_lAb}`

And we're done 



<br> <br>
[Back To Home](../../index.md)
<br>

