### Binary Exploitation

### Source: ROP Emporium

### Name: Split (x86 & x64)

### Basic File Checks

```
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/split/32bit]
└─$ file split 
split: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=76cb700a2ac0484fb4fa83171a17689b37b9ee8d, not stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/split/32bit]
└─$ checksec split
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/RopEmperium/split/32bit/split'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We're working with a x86 binary and the protections enabled is just NX

I'll run the binary to get an overview of what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/split/32bit]
└─$ ./split
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> lol
Thank you!

Exiting
```

So it prints out some words then asks for input then exits after we give it input

Decompiling using ghidra i’ll read the main function

```

undefined4 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("split by ROP Emporium");
  puts("x86\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

So the main function calls the pwnme() function

Here’s the decompiled pwnme function

```

void pwnme(void)

{
  undefined input [40];
  
  memset(input,0,0x20);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,input,0x60);
  puts("Thank you!");
  return;
}
```

So reading the code we get the vulnerability that is in it, it reads 0x60 bytes of data into a 40 bytes input buffer

With this we have 16 extra bytes which will cause an overflow

Looking through the code i get another function called `usefulFunction`
