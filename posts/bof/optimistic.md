### Binary Exploitation

### Source: HackTheBox

### Description: Are you ready to feel positive?

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/optimistic]
└─$ chmod +x optimistic 
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/optimistic]
└─$ file optimistic 
optimistic: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=24f4b065a2eab20657772e85de2af83b2f6fe8b1, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/optimistic]
└─$ checksec optimistic 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/optimistic/optimistic'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

So we're working with a x64 binary which has only the protection of PIE enabled

With NX enabled we can inject shellcode to the stack and execute it

I'll run the binary to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/optimistic]
└─$ ./optimistic 
Welcome to the positive community!
We help you embrace optimism.
Would you like to enroll yourself? (y/n): n
Too bad, see you next time :(
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/optimistic]
└─$ ./optimistic
Welcome to the positive community!
We help you embrace optimism.
Would you like to enroll yourself? (y/n): y
Great! Here's a small welcome gift: 0x7fffffffdea0
Please provide your details.
Email: pwner@lol.com
Age: Length of name: 10
Name: haxor
Thank you! We'll be in touch soon.
```

We see it proves to create some sort of login lol and also i'll take note of the stack address leaked 

Decompiling using ghidra

```
void main(void)

{
  int iVar1;
  ssize_t age;
  uint len_username;
  undefined4 local_80;
  undefined2 local_7c;
  char option;
  undefined local_79;
  undefined auStack120 [8];
  undefined auStack112 [8];
  char local_68 [96];
  
  initialize();
  puts("Welcome to the positive community!");
  puts("We help you embrace optimism.");
  printf("Would you like to enroll yourself? (y/n): ");
  iVar1 = getchar();
  option = (char)iVar1;
  getchar();
  if (option != 'y') {
    puts("Too bad, see you next time :(");
    local_79 = 0x6e;
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  printf("Great! Here\'s a small welcome gift: %p\n",&stack0xfffffffffffffff8);
  puts("Please provide your details.");
  printf("Email: ");
  age = read(0,auStack120,8);
  local_7c = (undefined2)age;
  printf("Age: ");
  age = read(0,auStack112,8);
  local_80 = (undefined4)age;
  printf("Length of name: ");
  __isoc99_scanf(&DAT_00102104,&len_username);
  if (0x40 < (int)len_username) {
    puts("Woah there! You shouldn\'t be too optimistic.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  printf("Name: ");
  age = read(0,local_68,(ulong)len_username);
  len_username = 0;
  while( true ) {
    if ((int)age + -9 <= (int)len_username) {
      puts("Thank you! We\'ll be in touch soon.");
      return;
    }
    iVar1 = isalpha((int)local_68[(int)len_username]);
    if ((iVar1 == 0) && (9 < (int)local_68[(int)len_username] - 0x30U)) break;
    len_username = len_username + 1;
  }
  puts("Sorry, that\'s an invalid name.");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
                                               
