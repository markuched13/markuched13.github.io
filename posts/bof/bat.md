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

I'll hop on to gdb and set a breakpoint on main and the leave call 

```


