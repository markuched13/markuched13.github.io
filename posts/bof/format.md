### Format HackTheBox

### Difficulty = Easy

### Description: Can you hear the echo?

### Basic File Checks

```
┌──(venv)─(mark__haxor)-[~/_/BofLearn/Challs/HTB/format]
└─$ file format                                             
format: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5d38e04d29b4aae722164869f3151cea776ce91c, for GNU/Linux 3.2.0, not stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/BofLearn/Challs/HTB/format]
└─$ checksec format
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/format/format'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We're working with a x64 binary and it has all protections enabled so we're not dealing with a buffer overflow

Decompiling using ghidra and checking the main function

```
undefined8 main(EVP_PKEY_CTX *param_1)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  echo();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

It calls the echo() function. Here's the decompiled code for it

```
void echo(void)

{
  long in_FS_OFFSET;
  char input [264];
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  do {
    fgets(input,0x100,stdin);
    printf(input);
  } while( true );
}

```

Her'
