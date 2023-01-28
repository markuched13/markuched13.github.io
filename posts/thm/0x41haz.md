### 0x41haz TryHackMe

### Difficulty = Easy

### Description: In this challenge, you are asked to solve a simple reversing solution. Download and analyze the binary to discover the password. There may be anti-reversing measures in place!

So lets download the binary and reverse it 

Checking the file type

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ chmod +x 0x41haz.0x41haz 
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ file 0x41haz.0x41haz 
0x41haz.0x41haz: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
```

Hmmm we can't really see the the file type

Lets use checksec to know get more about the file

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ checksec --file=0x41haz
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX disabled   Not an ELF file   No RPATH   No RUNPATH   No Symbols      No    0               0               0x41haz
```

Ah it shows that it is not an elf file 

Now from this we can tell there's `Anti-Reverse Engineering Features`

So we need to patch the binary first

To do that we need to set the sixth byte to `01` cause its in `02`

That can be done using hexeditor

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ hexeditor 0x41haz

File: 0x41haz                                                                                                                                                        ASCII Offset: 0x00000000 / 0x0000385F (%00)   
00000000  7F 45 4C 46  02 02 01 00   00 00 00 00  00 00 00 00                                                                                                                                      .ELF............
00000010  03 00 3E 00  01 00 00 00   80 10 00 00  00 00 00 00                                                                                                                                      ..>.............
00000020  40 00 00 00  00 00 00 00   60 31 00 00  00 00 00 00                                                                                                                                      @.......`1......
00000030  00 00 00 00  40 00 38 00   0B 00 40 00  1C 00 1B 00                                                                                                                                      ....@.8...@.....
00000040  06 00 00 00  04 00 00 00   40 00 00 00  00 00 00 00                                                                                                                                      ........@.......
00000050  40 00 00 00  00 00 00 00   40 00 00 00  00 00 00 00                                                                                                                                      @.......@.......
00000060  68 02 00 00  00 00 00 00   68 02 00 00  00 00 00 00        
```

Now after patching it here's how the hex byte should look like

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ hexeditor 0x41haz

File: 0x41haz                                                                                                                                                        ASCII Offset: 0x00000000 / 0x0000385F (%00)   
00000000  7F 45 4C 46  02 01 01 00   00 00 00 00  00 00 00 00                                                                                                                                      .ELF............
00000010  03 00 3E 00  01 00 00 00   80 10 00 00  00 00 00 00                                                                                                                                      ..>.............
00000020  40 00 00 00  00 00 00 00   60 31 00 00  00 00 00 00                                                                                                                                      @.......`1......
00000030  00 00 00 00  40 00 38 00   0B 00 40 00  1C 00 1B 00                                                                                                                                      ....@.8...@.....
00000040  06 00 00 00  04 00 00 00   40 00 00 00  00 00 00 00                                                                                                                                      ........@.......
00000050  40 00 00 00  00 00 00 00   40 00 00 00  00 00 00 00                                                                                                                                      @.......@.......
00000060  68 02 00 00  00 00 00 00   68 02 00 00  00 00 00 00        
```

Now lets check the file type again

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ file 0x41haz        
0x41haz: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c9f2e85b64d4f12b91136ffb8e4c038f1dc6dcd, for GNU/Linux 3.2.0, stripped
```

Now we can run it

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ ./0x41haz 
=======================
Hey , Can You Crackme ?
=======================
It's jus a simple binary 

Tell Me the Password :
test
Is it correct , I don't think so.
```

Cool here's decompile it using ghidra

On looking at `FUN_00101165` which is likely the `main` function
![image](https://user-images.githubusercontent.com/113513376/215273702-568f0aea-e769-4911-b583-869fa514f761.png)

So i'll try to rename it to how the original C code will look

```

int main(void)

{
  size_t length;
  char input [42];
  undefined8 local_1e;
  undefined4 local_16;
  undefined2 local_12;
  int decimal;
  int i;
  
  local_1e = 0x6667243532404032;
  local_16 = 0x40265473;
  local_12 = 0x4c;
  puts("=======================\nHey , Can You Crackme ?\n=======================");
  puts("It\'s jus a simple binary \n");
  puts("Tell Me the Password :");
  gets(input);
  length = strlen(input);
  decimal = (int)length;
  if ((int)length != 0xd) {
    puts("Is it correct , I don\'t think so.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  i = 0;
  while( true ) {
    if (0xc < i) {
      puts("Well Done !!");
      return 0;
    }
    if (*(char *)((long)&local_1e + (long)i) != input[i]) break;
    i = i + 1;
  }
  puts("Nope");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

So here's what it does

```
1. It saves some hexadecimal values on the stack
2. It then prints out the logo and asks for input
3. After getting the user input it checks the length and saves it in a variable 
4. Then it finds the interger value of the input i.e hacker == 6
5. It then does an if check that confirms if the length is not equal to 13 it prints is it correct?
6. But if the length is 13 it does a loop for 12 times 
7. While it loops if the input isn't the correct password it prints Nope
8. Then it exits after getting the correct password
```

So we know there are hexadecimal values being stored on the stack

Lets decode it

But because of x64 endianess we will start decoding from the last value

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ cat pass              
0x4c0x402654730x6667243532404032
```

Now lets decode it using `xxd`

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ cat pass | xxd -r | rev
2@@25$gfsT&@L 
```

Now lets give this `2@@25$gfsT&@L` as the password

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/0x41haz]
└─$ ./0x41haz
=======================
Hey , Can You Crackme ?
=======================
It's jus a simple binary 

Tell Me the Password :
2@@25$gfsT&@L
Well Done !!
```

And it worked cool

Here's the flag

Flag: `THM{2@@25$gfsT&@L}`


And we're done


<br> <br>
[Back To Home](../../index.md)
<br>




                                    
