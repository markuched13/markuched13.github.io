### Buffer Overflow Practice

### Source: CSAW18

### Basic File Check

```
┌──(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ file boi     
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
                                                                                                                                                                                                                                                                                                                                                                                                                                    
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ checksec boi     
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

We're working with a x64 binary which is dynamically linked and non stripped 

It has canary & NX enabled as its protection

Lets run it to see what it does

```
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./boi    
Are you a big boiiiii??
yes
Sun 29 Jan 2023 12:27:34 WAT
                                                                                                                                                                                                                  
┌──(venv)─(mark__haxor)-[~/Documents/Pentest/BOF/03-begineer_bof]
└─$ ./boi
Are you a big boiiiii??
no
Sun 29 Jan 2023 12:27:36 WAT
```

It justs asks if you are a boy then prints the current date after it receives input

I'll decompile the binary using ghidra

On checking the main function here's what i get (P.S-> I'll try to edit the binary for proper understanding)

```
int main(void)

{
  long in_FS_OFFSET;
  undefined8 input;
  undefined8 local_30;
  undefined4 uStack40;
  int expectedValue;
  undefined4 local_20;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  input = 0;
  local_30 = 0;
  local_20 = 0;
  uStack40 = 0;
  expectedValue = L'\xdeadbeef;
  puts("Are you a big boiiiii??");
  read(0,&input,0x18);
  if (expectedValue == L'\xcaf3baee') {
    run_cmd("/bin/bash");
  }
  else {
    run_cmd("/bin/date");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

From this we know that

```
1. It asks for our input which then scans 0x18 bytes of data into input
2. But before the call of input it stores 0xdeadbeef in a variable
3. Then after it reads the user input, it compares the expectedValue with 0xcaf3baee
```

Now to see where our input reached i'll take a look at the stack from ghidra

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __stdcall main(void)
             int               EAX:4          <RETURN>
             undefined8        Stack[-0x10]:8 canary                                  XREF[2]:     00400659(W), 
                                                                                                   004006ca(R)  
             undefined4        Stack[-0x20]:4 local_20                                XREF[1]:     00400677(W)  
             undefined4        Stack[-0x24]:4 expectedValue                           XREF[2]:     0040067e(W), 
                                                                                                   004006a5(R)  
             undefined8        Stack[-0x30]:8 local_30                                XREF[1]:     00400667(W)  
             undefined8        Stack[-0x38]:8 input                                   XREF[2]:     0040065f(W), 
                                                                                                   0040068f(*)  
             undefined4        Stack[-0x3c]:4 local_3c                                XREF[1]:     00400649(W)  
             undefined8        Stack[-0x48]:8 local_48                                XREF[1]:     0040064c(W)  
                             main                                            XREF[5]:     Entry Point(*), 
                                                                                          _start:0040054d(*), 
                                                                                          _start:0040054d(*), 004007b4, 
                                                                                          00400868(*)  
        00400641 55              PUSH       RBP
```

Looking at the ghidra output we see that:

```
1. The input is stored at offset -0x38
2. The expectedValue is stored at offset -0x24
3. And the difference between the valud of the input nd expectedValue is 0x14
```

We have extra 0x4 bytes 

From this we know that we can since we have 0x18 bytes to write we can fill up the 0x14 bytes and overwrite target with 0x4 byte

Here's the bug, since we are given 0x18 which is then written in a 0x14 space making 0x4 bytes overflown in target

That gives us the ability to control the value

Lets hope on to gdb 

```
