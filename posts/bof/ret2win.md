### Binary Exploitation

### Source: ROP Emporium

### Name: Ret2Win (x86 & x64)

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/ret2win/32bits]
└─$ file ret2win
ret2win: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped
                                                                                                                                                                                            
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/ret2win/32bits]
└─$ checksec ret2win
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/RopEmperium/ret2win/32bits/ret2win'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Cool so we're working with a x86 binary and its protection is only NX enabled

I'll run to get a quick overview of what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Challs/RopEmperium/ret2win/32bits]
└─$ ./ret2win             
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> lol
Thank you!

Exiting
```

So it prints out some words then asks for input then exits after we give it input

Decompiling using ghidra i'll read the main function

```

undefined4 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("ret2win by ROP Emporium");
  puts("x86\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

So the main function calls the pwnme() function

He
