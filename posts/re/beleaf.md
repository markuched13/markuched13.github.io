### Reverse Engineering 

### Basic File Checks

I'll check the file type
```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ file csaw19_beleaf  
csaw19_beleaf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6d305eed7c9bebbaa60b67403a6c6f2b36de3ca4, stripped
```

It's a x64 binary which is dynamically linked and its stripped

Now checking the protection enabled

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ checksec csaw19_beleaf 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/02-beginner_re/csaw19_beleaf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So lets run it to know what it does

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/02-beginner_re]
└─$ ./csaw19_beleaf                   
Enter the flag
>>> flag
Incorrect!
```

It requires inputting the flag

Now i'll decompile it using ghidra

On checking `FUN_001008a1` which is going to be the main function we get this

```

undefined8 FUN_001008a1(void)

{
  size_t sVar1;
  long lVar2;
  long in_FS_OFFSET;
  ulong local_b0;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter the flag\n>>> ");
  __isoc99_scanf(&DAT_00100a78,local_98);
  sVar1 = strlen(local_98);
  if (sVar1 < 0x21) {
    puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  for (local_b0 = 0; local_b0 < sVar1; local_b0 = local_b0 + 1) {
    lVar2 = FUN_001007fa((int)local_98[local_b0]);
    if (lVar2 != *(long *)(&DAT_003014e0 + local_b0 * 8)) {
      puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
  }
  puts("Correct!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Now i'll try to rename stuffs there to make it look better

```
int main(void)

{
  size_t len;
  long transformInput;
  long in_FS_OFFSET;
  ulong i;
  char input [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter the flag\n>>> ");
  __isoc99_scanf(&DAT_00100a78,input);
  len = strlen(input);
  if (len < 0x21) {
    puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  for (i = 0; i < len; i = i + 1) {
    transformInput = transformFunc((int)input[i]);
    if (transformInput != *(long *)(&desiredOutput + i * 8)) {
      puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
  }
  puts("Correct!");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

Now that looks better. So here's what happening

```
1. It receives user input then check if the length is less than 33 if it is, it prints incorrect then exit
2. But if it isn't, it does a for loop on the length of the input given
3. while it loops it runs through each character of the input and the tranformFunc compares it with the desiredOutput value
4. Also the desiredOutput characters is stored as an offset of 8bytes
5. If the two are not equal the program exists
6. Checking the tranformFunc shows that the data in stored in the .bss section of the binary
```

Now we know that our first output is going to be equal to 0x1, the second wil be 0x9 and so on .....

```
                             desiredOutput                                   XREF[2]:     main:0010096b(*), 
                                                                                          main:00100972(R)  
        003014e0 01              ??         01h
        003014e1 00              ??         00h
        003014e2 00              ??         00h
        003014e3 00              ??         00h
        003014e4 00              ??         00h
        003014e5 00              ??         00h
        003014e6 00              ??         00h
        003014e7 00              ??         00h
        003014e8 09              ??         09h
        003014e9 00              ??         00h
        003014ea 00              ??         00h
        003014eb 00              ??         00h
        003014ec 00              ??         00h
        003014ed 00              ??         00h
        003014ee 00              ??         00h
        003014ef 00              ??         00h
        003014f0 11              ??         11h
        003014f1 00              ??         00h
        003014f2 00              ??         00h
        003014f3 00              ??         00h
        003014f4 00              ??         00h
        003014f5 00              ??         00h
        003014f6 00              ??         00h
        003014f7 00              ??         00h
        003014f8 27              ??         27h    '
        003014f9 00              ??         00h
```

Here's the decompiled code for the transformFunc

```

long transformFunc(char input)

{
  long i;
  
  i = 0;
  while ((i != -1 && ((int)input != *(int *)(&lookup + i * 4)))) {
    if ((int)input < *(int *)(&lookup + i * 4)) {
      i = i * 2 + 1;
    }
    else if (*(int *)(&lookup + i * 4) < (int)input) {
      i = (i + 1) * 2;
    }
  }
  return i;
}

```






