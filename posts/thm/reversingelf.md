### Reversing ELF TryHackMe

### Crackme1

### Description: Let's start with a basic warmup, can you run the binary?

After downloading the binary lets check the file type 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme1   
crackme1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=672f525a7ad3c33f190c060c09b11e9ffd007f34, not stripped
```

Now lets run it and see what it does

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme1                             
flag{not_that_kind_of_elf}
```

It prints the flag out cool

Flag: `flag{not_that_kind_of_elf}`

### Crackme2

### Description: Find the super-secret password! and use it to obtain the flag

After downloading the binary lets check the file type 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme2
crackme2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b799eb348f3df15f6b08b3c37f8feb269a60aba7, not stripped
 ```
 
 So now lets check what it does by running it
 
 ```
 ┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme2 
Usage: ./crackme2 password
```

It requires a password. I'll run strings on it to see if i'll get anything interesting

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ strings crackme2             
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
puts
printf
memset
strcmp
__libc_start_main
/usr/local/lib:$ORIGIN
__gmon_start__
GLIBC_2.0
PTRh 
j3jA
[^_]
UWVS
t$,U
[^_]
Usage: %s password
super_secret_password
Access denied.
Access granted.
;*2$"(
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609
crtstuff.c
__JCR_LIST__
deregister_tm_clones
__do_global_dtors_aux
completed.7209
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
conditional1.c
giveFlag
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
strcmp@@GLIBC_2.0
_ITM_deregisterTMCloneTable
__x86.get_pc_thunk.bx
printf@@GLIBC_2.0
_edata
__data_start
puts@@GLIBC_2.0
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_start_main@@GLIBC_2.0
__libc_csu_init
memset@@GLIBC_2.0
_fp_hw
__bss_start
main
_Jv_RegisterClasses
__TMC_END__
_ITM_registerTMCloneTable
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rel.dyn
.rel.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got.plt
.data
.bss
.comment
 ```
 
 Nice we see the password is `super_secret_password`
 
 Lets confirm 
 
 ```
 ┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme2 super_secret_password
Access granted.
flag{if_i_submit_this_flag_then_i_will_get_points}
```

Cool we have the flag 

Flag: `flag{if_i_submit_this_flag_then_i_will_get_points}`

### Crackme3

### Description: Use basic reverse engineering skills to obtain the flag

As usual i'll download the binary and check its file type

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme3
crackme3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4cf7250afb50109f0f1a01cc543fbf5ba6204a73, stripped
```
  
Now i'll run it and see what it does

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme3                      
Usage: ./crackme3 PASSWORD
```

It requires a password 

Running strings shows a base64 encoded string

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ strings crackme3
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
puts
strlen
malloc
stderr
fwrite
fprintf
strcmp
__libc_start_main
GLIBC_2.0
PTRh
iD$$
D$,;D$ 
UWVS
[^_]
Usage: %s PASSWORD
malloc failed
ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==
Correct password!
Come on, even my aunt Mildred got this one!
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
;*2$"8
GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rel.dyn
.rel.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.ctors
.dtors
.jcr
.dynamic
.got
.got.plt
.data
.bss
.comment
```

Encoded value = `ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==`

I'll decode it and then try it as the password

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ echo "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d
f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5                                                                                                                                                                                                                   
```

Now trying it as the password 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme3 f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5
Correct password!
```

Cool here's the flag

Flag: `f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5`

### Crackme4

### Description: Analyze and find the password for the binary?

Cool checking the file type 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme4
crackme4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=862ee37793af334043b423ba50ec91cfa132260a, not stripped
```

Running it to see what it does

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme4                                               
Usage : ./crackme4 password
This time the string is hidden and we used strcmp
```
 
 We're given a big hint that the program uses string compare 
 
 Now lets run ltrace on the binary
 
 ```
 ┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ltrace ./crackme4 test   
__libc_start_main(0x400716, 2, 0x7ffd14e2aba8, 0x400760 <unfinished ...>
strcmp("my_m0r3_secur3_pwd", "test")                                                                                              = -7
printf("password "%s" not OK\n", "test"password "test" not OK
)                                                                                          = 23
+++ exited (status 0) +++
```

Now we have the correct password lets validate this 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme4 my_m0r3_secur3_pwd
password OK
```

Flag: `my_m0r3_secur3_pwd`

### Crackme5

### Description: What will be the input of the file to get output Good game ?

I'll download the binary and check its file type 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme5                
crackme5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a426dcf8ed3de8cb02f3ee4f38ee36b4ed568519, not stripped
```

Now i'll run it do see what it does

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme5                   
Enter your input:
lol 
Always dig deeper
```

Checking strings doesn't give anything or ltrace

So lets fire up gdb 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ gdb -q ./crackme5
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from ./crackme5...
(No debugging symbols found in ./crackme5)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000400528  _init
0x0000000000400560  strncmp@plt
0x0000000000400570  puts@plt
0x0000000000400580  strlen@plt
0x0000000000400590  __stack_chk_fail@plt
0x00000000004005a0  __libc_start_main@plt
0x00000000004005b0  atoi@plt
0x00000000004005c0  __isoc99_scanf@plt
0x00000000004005d0  __gmon_start__@plt
0x00000000004005e0  _start
0x0000000000400610  deregister_tm_clones
0x0000000000400650  register_tm_clones
0x0000000000400690  __do_global_dtors_aux
0x00000000004006b0  frame_dummy
0x00000000004006d6  strcmp_
0x0000000000400773  main
0x000000000040086e  check
0x00000000004008d0  __libc_csu_init
0x0000000000400940  __libc_csu_fini
0x0000000000400944  _fini
gef➤
```

We see only 2 functions that are of interest to us which are `main` & `check`

Lets disassemble main

```
gef➤  disass main
Dump of assembler code for function main:
   0x0000000000400773 <+0>:     push   rbp
   0x0000000000400774 <+1>:     mov    rbp,rsp
   0x0000000000400777 <+4>:     sub    rsp,0x70
   0x000000000040077b <+8>:     mov    DWORD PTR [rbp-0x64],edi
   0x000000000040077e <+11>:    mov    QWORD PTR [rbp-0x70],rsi
   0x0000000000400782 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x000000000040078b <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040078f <+28>:    xor    eax,eax
   0x0000000000400791 <+30>:    mov    BYTE PTR [rbp-0x30],0x4f
   0x0000000000400795 <+34>:    mov    BYTE PTR [rbp-0x2f],0x66
   0x0000000000400799 <+38>:    mov    BYTE PTR [rbp-0x2e],0x64
   0x000000000040079d <+42>:    mov    BYTE PTR [rbp-0x2d],0x6c
   0x00000000004007a1 <+46>:    mov    BYTE PTR [rbp-0x2c],0x44
   0x00000000004007a5 <+50>:    mov    BYTE PTR [rbp-0x2b],0x53
   0x00000000004007a9 <+54>:    mov    BYTE PTR [rbp-0x2a],0x41
   0x00000000004007ad <+58>:    mov    BYTE PTR [rbp-0x29],0x7c
   0x00000000004007b1 <+62>:    mov    BYTE PTR [rbp-0x28],0x33
   0x00000000004007b5 <+66>:    mov    BYTE PTR [rbp-0x27],0x74
   0x00000000004007b9 <+70>:    mov    BYTE PTR [rbp-0x26],0x58
   0x00000000004007bd <+74>:    mov    BYTE PTR [rbp-0x25],0x62
   0x00000000004007c1 <+78>:    mov    BYTE PTR [rbp-0x24],0x33
   0x00000000004007c5 <+82>:    mov    BYTE PTR [rbp-0x23],0x32
   0x00000000004007c9 <+86>:    mov    BYTE PTR [rbp-0x22],0x7e
   0x00000000004007cd <+90>:    mov    BYTE PTR [rbp-0x21],0x58
   0x00000000004007d1 <+94>:    mov    BYTE PTR [rbp-0x20],0x33
   0x00000000004007d5 <+98>:    mov    BYTE PTR [rbp-0x1f],0x74
   0x00000000004007d9 <+102>:   mov    BYTE PTR [rbp-0x1e],0x58
   0x00000000004007dd <+106>:   mov    BYTE PTR [rbp-0x1d],0x40
   0x00000000004007e1 <+110>:   mov    BYTE PTR [rbp-0x1c],0x73
   0x00000000004007e5 <+114>:   mov    BYTE PTR [rbp-0x1b],0x58
   0x00000000004007e9 <+118>:   mov    BYTE PTR [rbp-0x1a],0x60
   0x00000000004007ed <+122>:   mov    BYTE PTR [rbp-0x19],0x34
   0x00000000004007f1 <+126>:   mov    BYTE PTR [rbp-0x18],0x74
   0x00000000004007f5 <+130>:   mov    BYTE PTR [rbp-0x17],0x58
   0x00000000004007f9 <+134>:   mov    BYTE PTR [rbp-0x16],0x74
   0x00000000004007fd <+138>:   mov    BYTE PTR [rbp-0x15],0x7a
   0x0000000000400801 <+142>:   mov    edi,0x400954
   0x0000000000400806 <+147>:   call   0x400570 <puts@plt>
   0x000000000040080b <+152>:   lea    rax,[rbp-0x50]
   0x000000000040080f <+156>:   mov    rsi,rax
   0x0000000000400812 <+159>:   mov    edi,0x400966
   0x0000000000400817 <+164>:   mov    eax,0x0
   0x000000000040081c <+169>:   call   0x4005c0 <__isoc99_scanf@plt>
   0x0000000000400821 <+174>:   lea    rdx,[rbp-0x30]
   0x0000000000400825 <+178>:   lea    rax,[rbp-0x50]
   0x0000000000400829 <+182>:   mov    rsi,rdx
   0x000000000040082c <+185>:   mov    rdi,rax
   0x000000000040082f <+188>:   call   0x4006d6 <strcmp_>
   0x0000000000400834 <+193>:   mov    DWORD PTR [rbp-0x54],eax
   0x0000000000400837 <+196>:   cmp    DWORD PTR [rbp-0x54],0x0
   0x000000000040083b <+200>:   jne    0x400849 <main+214>
   0x000000000040083d <+202>:   mov    edi,0x400969
   0x0000000000400842 <+207>:   call   0x400570 <puts@plt>
   0x0000000000400847 <+212>:   jmp    0x400853 <main+224>
   0x0000000000400849 <+214>:   mov    edi,0x400973
   0x000000000040084e <+219>:   call   0x400570 <puts@plt>
   0x0000000000400853 <+224>:   mov    eax,0x0
   0x0000000000400858 <+229>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000040085c <+233>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000400865 <+242>:   je     0x40086c <main+249>
   0x0000000000400867 <+244>:   call   0x400590 <__stack_chk_fail@plt>
   0x000000000040086c <+249>:   leave  
   0x000000000040086d <+250>:   ret    
End of assembler dump.
gef➤  
```

We see some values are being stored in a variable 

So i'll decode those hexadecimal values by writing a python script that would do that

Here's the script 

```
#!/usr/bin/env python3
datas = ['0x4f', '0x66', '0x64', '0x6c', '0x44', '0x53', '0x41', '0x7c', '0x33', '0x74', '0x58', '0x62', '0x33', '0x32', '0x7e', '0x58', '0x33', '0x74', '0x58', '0x40', '0x73', '0x58', '0x60', '0x34', '0x74', '0x58', '0x74', '0x7a']
decoded_string = ''

for i in datas:
    try:
        decimal_value = int(i, 16)
        if decimal_value < 128:
            decoded_string += chr(decimal_value)
    except ValueError:
        print(f"{i} is not a hexadecimal number, skipping.")
    except:
        print(f"Unexpected error occured in {i}, skipping.")

print(decoded_string)
```

On running it we get all the ascii printable characters 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ python3 crackme5.py 
OfdlDSA|3tXb32~X3tX@sX`4tXtz

```

Now lets give the binary this input

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme5
Enter your input:
OfdlDSA|3tXb32~X3tX@sX`4tXtz
Good game
```

Well it worked. So the input is

Input: `OfdlDSA|3tXb32~X3tX@sX`4tXtz`

### Crackme6 

### Description: Analyze the binary for the easy password

So as usual i'll download the binary then check the file type

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme6
crackme6: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=022f1a8e479cab9f7263af75bcdbb328bda7f291, not stripped
```

Now lets check out what the binary does

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme6
Usage : ./crackme6 password
Good luck, read the source
```

We're given hint to read the source code 

So i'll open this binary up in ghidra to decompile it

So on checking the main function we get this
![image](https://user-images.githubusercontent.com/113513376/215239291-aec06ba2-e752-4833-872e-70e5e05537d0.png)

So i'll try to rewrite it

```
int main(int argc,char **argv)
{
  if (argc == 2) {
    compare_pwd(argv[1]);
  }
  else {
    printf("Usage : %s password\nGood luck, read the source\n",*argv);
  }
  return 0;
}
```

So what the main function just does is that

```
1. It checks if the argument count is equal to 2 i.e the binary + the input 
2. If that is true it then calls the compare_pwd function and gives the password we input as the parameter the function should use
3. But if its false it then prints the usage on how to run the binary
```

Now lets check out the compare_pwd function
![image](https://user-images.githubusercontent.com/113513376/215239527-1b4766ea-4997-4132-b377-4f000950d120.png)

I'll try to edit it to how the main C code is supposed to look

```
void compare_pwd(char **input)
{
  int password_check;
  
  password_check = my_secure_test(input);
  if (password_check == 0) {
    puts("password OK");
  }
  else {
    printf("password \"%s\" not OK\n",input);
  }
  return;
}
```

Now what this does is this

```
1. It uses the argument we passed on earlier then it calls another function called my_secure_test 
2. It then checks if the password we passed into is the same as the password in mysecuretest
3. If it is it prints password ok
4. But if it isn't it prints password notoky
```

Time to check out the other function where the password is stored
![image](https://user-images.githubusercontent.com/113513376/215239822-c9da22e6-ed76-4bc6-b7a6-b4c128908168.png)

Here's the code i tried re-editing

```

int my_secure_test(char *input)

{
  int error;
  
  if ((*input == '\0') || (*input != '1')) {
    error = -1;
  }
  else if ((input[1] == '\0') || (input[1] != '3')) {
    error = -1;
  }
  else if ((input[2] == '\0') || (input[2] != '3')) {
    error = -1;
  }
  else if ((input[3] == '\0') || (input[3] != '7')) {
    error = -1;
  }
  else if ((input[4] == '\0') || (input[4] != '_')) {
    error = -1;
  }
  else if ((input[5] == '\0') || (input[5] != 'p')) {
    error = -1;
  }
  else if ((input[6] == '\0') || (input[6] != 'w')) {
    error = -1;
  }
  else if ((input[7] == '\0') || (input[7] != 'd')) {
    error = -1;
  }
  else if (input[8] == '\0') {
    error = 0;
  }
  else {
    error = -1;
  }
  return error;
}
```

Here's what it does

```
1. It uses that same password we give as the compare argument
2. It then compares the password string with 1337_pwd
```

So now that we have a password lets use it and run the binary

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme6 1337_pwd
password OK
```

Cool so here's the flag

Flag: `1337_pwd`

### Crackme7

### Description: Analyze the binary to get the flag

As usual i'll download the binary and check its file type

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme7
crackme7: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7ee4206d91718e7b0bef16a7c03f8fa49c4a39e7, not stripped
```

Now lets run it to see what it does

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme7
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 1
What is your name? pwner
Hello, pwner!
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 2
Enter first number: 1
Enter second number: 2
1 + 2 = 3
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 3
Goodbye!
```

Cool so its just like an app which has 2 functions

```
1. To say hello for the username given
2. To perform addition arithmetic
```

Lets open the binary up in gdb

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ gdb -q ./crackme7
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from ./crackme7...
(No debugging symbols found in ./crackme7)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x08048324  _init
0x08048360  printf@plt
0x08048370  puts@plt
0x08048380  __libc_start_main@plt
0x08048390  memset@plt
0x080483a0  __isoc99_scanf@plt
0x080483b0  __gmon_start__@plt
0x080483c0  _start
0x080483f0  __x86.get_pc_thunk.bx
0x08048400  deregister_tm_clones
0x08048430  register_tm_clones
0x08048470  __do_global_dtors_aux
0x08048490  frame_dummy
0x080484bb  main
0x080486a6  giveFlag
0x08048740  __libc_csu_init
0x080487a0  __libc_csu_fini
0x080487a4  _fini
gef➤
```

We see there are two functions of interest

Which are the main function and the giveFlag function

Lets disassemble the main function

```
gef➤  disass main
Dump of assembler code for function main:
   0x080484bb <+0>:     lea    ecx,[esp+0x4]
   0x080484bf <+4>:     and    esp,0xfffffff0
   0x080484c2 <+7>:     push   DWORD PTR [ecx-0x4]
   0x080484c5 <+10>:    push   ebp
   0x080484c6 <+11>:    mov    ebp,esp
   0x080484c8 <+13>:    push   edi
   0x080484c9 <+14>:    push   ecx
   0x080484ca <+15>:    sub    esp,0x70
   0x080484cd <+18>:    sub    esp,0xc
   0x080484d0 <+21>:    push   0x80487e0
   0x080484d5 <+26>:    call   0x8048370 <puts@plt>
   0x080484da <+31>:    add    esp,0x10
   0x080484dd <+34>:    sub    esp,0xc
   0x080484e0 <+37>:    push   0x804880e
   0x080484e5 <+42>:    call   0x8048360 <printf@plt>
   0x080484ea <+47>:    add    esp,0x10
   0x080484ed <+50>:    sub    esp,0x8
   0x080484f0 <+53>:    lea    eax,[ebp-0xc]
   0x080484f3 <+56>:    push   eax
   0x080484f4 <+57>:    push   0x8048814
   0x080484f9 <+62>:    call   0x80483a0 <__isoc99_scanf@plt>
   0x080484fe <+67>:    add    esp,0x10
   0x08048501 <+70>:    cmp    eax,0x1
   0x08048504 <+73>:    je     0x8048520 <main+101>
   0x08048506 <+75>:    sub    esp,0xc
   0x08048509 <+78>:    push   0x8048817
   0x0804850e <+83>:    call   0x8048370 <puts@plt>
   0x08048513 <+88>:    add    esp,0x10
   0x08048516 <+91>:    mov    eax,0x1
   0x0804851b <+96>:    jmp    0x804869c <main+481>
   0x08048520 <+101>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08048523 <+104>:   cmp    eax,0x1
   0x08048526 <+107>:   jne    0x8048595 <main+218>
   0x08048528 <+109>:   sub    esp,0xc
   0x0804852b <+112>:   push   0x8048826
   0x08048530 <+117>:   call   0x8048360 <printf@plt>
   0x08048535 <+122>:   add    esp,0x10
   0x08048538 <+125>:   lea    edx,[ebp-0x78]
   0x0804853b <+128>:   mov    eax,0x0
   0x08048540 <+133>:   mov    ecx,0x19
   0x08048545 <+138>:   mov    edi,edx
   0x08048547 <+140>:   rep stos DWORD PTR es:[edi],eax
   0x08048549 <+142>:   sub    esp,0x8
   0x0804854c <+145>:   lea    eax,[ebp-0x78]
   0x0804854f <+148>:   push   eax
   0x08048550 <+149>:   push   0x804883a
   0x08048555 <+154>:   call   0x80483a0 <__isoc99_scanf@plt>
   0x0804855a <+159>:   add    esp,0x10
   0x0804855d <+162>:   cmp    eax,0x1
   0x08048560 <+165>:   je     0x804857c <main+193>
   0x08048562 <+167>:   sub    esp,0xc
   0x08048565 <+170>:   push   0x804883f
   0x0804856a <+175>:   call   0x8048370 <puts@plt>
   0x0804856f <+180>:   add    esp,0x10
   0x08048572 <+183>:   mov    eax,0x1
   0x08048577 <+188>:   jmp    0x804869c <main+481>
   0x0804857c <+193>:   sub    esp,0x8
   0x0804857f <+196>:   lea    eax,[ebp-0x78]
   0x08048582 <+199>:   push   eax
   0x08048583 <+200>:   push   0x8048854
   0x08048588 <+205>:   call   0x8048360 <printf@plt>
   0x0804858d <+210>:   add    esp,0x10
   0x08048590 <+213>:   jmp    0x80484cd <main+18>
   0x08048595 <+218>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08048598 <+221>:   cmp    eax,0x2
   0x0804859b <+224>:   jne    0x8048648 <main+397>
   0x080485a1 <+230>:   sub    esp,0xc
   0x080485a4 <+233>:   push   0x8048860
   0x080485a9 <+238>:   call   0x8048360 <printf@plt>
   0x080485ae <+243>:   add    esp,0x10
   0x080485b1 <+246>:   sub    esp,0x8
   0x080485b4 <+249>:   lea    eax,[ebp-0x10]
   0x080485b7 <+252>:   push   eax
   0x080485b8 <+253>:   push   0x8048875
   0x080485bd <+258>:   call   0x80483a0 <__isoc99_scanf@plt>
   0x080485c2 <+263>:   add    esp,0x10
   0x080485c5 <+266>:   cmp    eax,0x1
   0x080485c8 <+269>:   je     0x80485e4 <main+297>
   0x080485ca <+271>:   sub    esp,0xc
   0x080485cd <+274>:   push   0x8048878
   0x080485d2 <+279>:   call   0x8048370 <puts@plt>
   0x080485d7 <+284>:   add    esp,0x10
   0x080485da <+287>:   mov    eax,0x1
   0x080485df <+292>:   jmp    0x804869c <main+481>
   0x080485e4 <+297>:   sub    esp,0xc
   0x080485e7 <+300>:   push   0x804888f
   0x080485ec <+305>:   call   0x8048360 <printf@plt>
   0x080485f1 <+310>:   add    esp,0x10
   0x080485f4 <+313>:   sub    esp,0x8
   0x080485f7 <+316>:   lea    eax,[ebp-0x14]
   0x080485fa <+319>:   push   eax
   0x080485fb <+320>:   push   0x8048875
   0x08048600 <+325>:   call   0x80483a0 <__isoc99_scanf@plt>
   0x08048605 <+330>:   add    esp,0x10
   0x08048608 <+333>:   cmp    eax,0x1
   0x0804860b <+336>:   je     0x8048624 <main+361>
   0x0804860d <+338>:   sub    esp,0xc
   0x08048610 <+341>:   push   0x8048878
   0x08048615 <+346>:   call   0x8048370 <puts@plt>
   0x0804861a <+351>:   add    esp,0x10
   0x0804861d <+354>:   mov    eax,0x1
   0x08048622 <+359>:   jmp    0x804869c <main+481>
   0x08048624 <+361>:   mov    edx,DWORD PTR [ebp-0x10]
   0x08048627 <+364>:   mov    eax,DWORD PTR [ebp-0x14]
   0x0804862a <+367>:   lea    ecx,[edx+eax*1]
   0x0804862d <+370>:   mov    edx,DWORD PTR [ebp-0x14]
   0x08048630 <+373>:   mov    eax,DWORD PTR [ebp-0x10]
   0x08048633 <+376>:   push   ecx
   0x08048634 <+377>:   push   edx
   0x08048635 <+378>:   push   eax
   0x08048636 <+379>:   push   0x80488a5
   0x0804863b <+384>:   call   0x8048360 <printf@plt>
   0x08048640 <+389>:   add    esp,0x10
   0x08048643 <+392>:   jmp    0x80484cd <main+18>
   0x08048648 <+397>:   mov    eax,DWORD PTR [ebp-0xc]
   0x0804864b <+400>:   cmp    eax,0x3
   0x0804864e <+403>:   jne    0x8048662 <main+423>
   0x08048650 <+405>:   sub    esp,0xc
   0x08048653 <+408>:   push   0x80488b3
   0x08048658 <+413>:   call   0x8048370 <puts@plt>
   0x0804865d <+418>:   add    esp,0x10
   0x08048660 <+421>:   jmp    0x8048697 <main+476>
   0x08048662 <+423>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08048665 <+426>:   cmp    eax,0x7a69
   0x0804866a <+431>:   jne    0x8048683 <main+456>
   0x0804866c <+433>:   sub    esp,0xc
   0x0804866f <+436>:   push   0x80488bc
   0x08048674 <+441>:   call   0x8048370 <puts@plt>
   0x08048679 <+446>:   add    esp,0x10
   0x0804867c <+449>:   call   0x80486a6 <giveFlag>
   0x08048681 <+454>:   jmp    0x8048697 <main+476>
   0x08048683 <+456>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08048686 <+459>:   sub    esp,0x8
   0x08048689 <+462>:   push   eax
   0x0804868a <+463>:   push   0x80488cc
   0x0804868f <+468>:   call   0x8048360 <printf@plt>
   0x08048694 <+473>:   add    esp,0x10
   0x08048697 <+476>:   mov    eax,0x0
   0x0804869c <+481>:   lea    esp,[ebp-0x8]
   0x0804869f <+484>:   pop    ecx
   0x080486a0 <+485>:   pop    edi
   0x080486a1 <+486>:   pop    ebp
   0x080486a2 <+487>:   lea    esp,[ecx-0x4]
   0x080486a5 <+490>:   ret    
End of assembler dump.
gef➤
```

Cool we see the assembly code but what if of interest is `main+449` 

When we ran the code at some point we are suppose to have the flag 

Cause the diasssemble code shows that there's a call to the giveFlag function

But we didn't. Now lets set a breakpoint at main so that we can just jump to the call for giveFlag function

```
gef➤  break main
Breakpoint 1 at 0x80484ca
gef➤  r
Starting program: /home/mark/Desktop/B2B/THM/Reversingelf/crackme7 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7fc7000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x080484ca in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x80484bb  →  <main+0> lea ecx, [esp+0x4]
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xffffd0a0  →  0x00000001
$edx   : 0xffffd0c0  →  0xf7e1cff4  →  0x0021cd8c
$esp   : 0xffffd080  →  0xffffd0a0  →  0x00000001
$ebp   : 0xffffd088  →  0x00000000
$esi   : 0x8048740  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x80484ca  →  <main+15> sub esp, 0x70
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd080│+0x0000: 0xffffd0a0  →  0x00000001    ← $esp
0xffffd084│+0x0004: 0xf7ffcb80  →  0x00000000
0xffffd088│+0x0008: 0x00000000   ← $ebp
0xffffd08c│+0x000c: 0xf7c23295  →   add esp, 0x10
0xffffd090│+0x0010: 0x00000000
0xffffd094│+0x0014: 0x000070 ("p"?)
0xffffd098│+0x0018: 0xf7ffcff4  →  0x00033f14
0xffffd09c│+0x001c: 0xf7c23295  →   add esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80484c6 <main+11>        mov    ebp, esp
    0x80484c8 <main+13>        push   edi
    0x80484c9 <main+14>        push   ecx
 →  0x80484ca <main+15>        sub    esp, 0x70
    0x80484cd <main+18>        sub    esp, 0xc
    0x80484d0 <main+21>        push   0x80487e0
    0x80484d5 <main+26>        call   0x8048370 <puts@plt>
    0x80484da <main+31>        add    esp, 0x10
    0x80484dd <main+34>        sub    esp, 0xc
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "crackme7", stopped 0x80484ca in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80484ca → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Now lets jump to `main+449`  which has an address `0x0804867c`

```
gef➤  j *0x0804867c
Continuing at 0x804867c.
flag{much_reversing_very_ida_wow}
[Inferior 1 (process 48904) exited normally]
gef➤
```

Cool we have the flag 

Flag: `flag{much_reversing_very_ida_wow}`

### Crackme8

### Description: Analyze the binary and obtain the flag

As usual i'll download the binary and its file type

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ file crackme8
crackme8: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=fef76e38b5ff92ed0d08870ac523f9f3f8925a40, not stripped
```

Now lets run the binary to get an overview of what it does

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme8
Usage: ./crackme8 password
```

It needs a password. I'll run it and put an invalid password

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ ./crackme8 pwner
Access denied.
```

Now i'll open the binary up in gdb

```
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Reversingelf]
└─$ gdb -q ./crackme8
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
Reading symbols from ./crackme8...
(No debugging symbols found in ./crackme8)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x08048300  _init
0x08048340  printf@plt
0x08048350  puts@plt
0x08048360  __libc_start_main@plt
0x08048370  memset@plt
0x08048380  atoi@plt
0x08048390  __gmon_start__@plt
0x080483a0  _start
0x080483d0  __x86.get_pc_thunk.bx
0x080483e0  deregister_tm_clones
0x08048410  register_tm_clones
0x08048450  __do_global_dtors_aux
0x08048470  frame_dummy
0x0804849b  main
0x08048524  giveFlag
0x080485c0  __libc_csu_init
0x08048620  __libc_csu_fini
0x08048624  _fini
gef➤ 
```

Cool just like the previous one there's a giveFlag function

Lets disassemble the main function 

```
gef➤  disass main
Dump of assembler code for function main:
   0x0804849b <+0>:     lea    ecx,[esp+0x4]
   0x0804849f <+4>:     and    esp,0xfffffff0
   0x080484a2 <+7>:     push   DWORD PTR [ecx-0x4]
   0x080484a5 <+10>:    push   ebp
   0x080484a6 <+11>:    mov    ebp,esp
   0x080484a8 <+13>:    push   ecx
   0x080484a9 <+14>:    sub    esp,0x4
   0x080484ac <+17>:    mov    eax,ecx
   0x080484ae <+19>:    cmp    DWORD PTR [eax],0x2
   0x080484b1 <+22>:    je     0x80484d0 <main+53>
   0x080484b3 <+24>:    mov    eax,DWORD PTR [eax+0x4]
   0x080484b6 <+27>:    mov    eax,DWORD PTR [eax]
   0x080484b8 <+29>:    sub    esp,0x8
   0x080484bb <+32>:    push   eax
   0x080484bc <+33>:    push   0x8048660
   0x080484c1 <+38>:    call   0x8048340 <printf@plt>
   0x080484c6 <+43>:    add    esp,0x10
   0x080484c9 <+46>:    mov    eax,0x1
   0x080484ce <+51>:    jmp    0x804851c <main+129>
   0x080484d0 <+53>:    mov    eax,DWORD PTR [eax+0x4]
   0x080484d3 <+56>:    add    eax,0x4
   0x080484d6 <+59>:    mov    eax,DWORD PTR [eax]
   0x080484d8 <+61>:    sub    esp,0xc
   0x080484db <+64>:    push   eax
   0x080484dc <+65>:    call   0x8048380 <atoi@plt>
   0x080484e1 <+70>:    add    esp,0x10
   0x080484e4 <+73>:    cmp    eax,0xcafef00d
   0x080484e9 <+78>:    je     0x8048502 <main+103>
   0x080484eb <+80>:    sub    esp,0xc
   0x080484ee <+83>:    push   0x8048674
   0x080484f3 <+88>:    call   0x8048350 <puts@plt>
   0x080484f8 <+93>:    add    esp,0x10
   0x080484fb <+96>:    mov    eax,0x1
   0x08048500 <+101>:   jmp    0x804851c <main+129>
   0x08048502 <+103>:   sub    esp,0xc
   0x08048505 <+106>:   push   0x8048683
   0x0804850a <+111>:   call   0x8048350 <puts@plt>
   0x0804850f <+116>:   add    esp,0x10
   0x08048512 <+119>:   call   0x8048524 <giveFlag>
   0x08048517 <+124>:   mov    eax,0x0
   0x0804851c <+129>:   mov    ecx,DWORD PTR [ebp-0x4]
   0x0804851f <+132>:   leave  
   0x08048520 <+133>:   lea    esp,[ecx-0x4]
   0x08048523 <+136>:   ret    
End of assembler dump.
gef➤
```

Cool we see it calls the giveFlag at some point 

So i'll set a breakpoint at main and jump to the giveFlag

```
gef➤  b main
Breakpoint 1 at 0x80484a9
gef➤  r
Starting program: /home/mark/Desktop/B2B/THM/Reversingelf/crackme8 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7fc7000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x080484a9 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x804849b  →  <main+0> lea ecx, [esp+0x4]
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xffffd0a0  →  0x00000001
$edx   : 0xffffd0c0  →  0xf7e1cff4  →  0x0021cd8c
$esp   : 0xffffd084  →  0xffffd0a0  →  0x00000001
$ebp   : 0xffffd088  →  0x00000000
$esi   : 0x80485c0  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x80484a9  →  <main+14> sub esp, 0x4
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd084│+0x0000: 0xffffd0a0  →  0x00000001    ← $esp
0xffffd088│+0x0004: 0x00000000   ← $ebp
0xffffd08c│+0x0008: 0xf7c23295  →   add esp, 0x10
0xffffd090│+0x000c: 0x00000000
0xffffd094│+0x0010: 0x000070 ("p"?)
0xffffd098│+0x0014: 0xf7ffcff4  →  0x00033f14
0xffffd09c│+0x0018: 0xf7c23295  →   add esp, 0x10
0xffffd0a0│+0x001c: 0x00000001
─────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80484a5 <main+10>        push   ebp
    0x80484a6 <main+11>        mov    ebp, esp
    0x80484a8 <main+13>        push   ecx
 →  0x80484a9 <main+14>        sub    esp, 0x4
    0x80484ac <main+17>        mov    eax, ecx
    0x80484ae <main+19>        cmp    DWORD PTR [eax], 0x2
    0x80484b1 <main+22>        je     0x80484d0 <main+53>
    0x80484b3 <main+24>        mov    eax, DWORD PTR [eax+0x4]
    0x80484b6 <main+27>        mov    eax, DWORD PTR [eax]
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "crackme8", stopped 0x80484a9 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80484a9 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  j *0x08048512
Continuing at 0x8048512.
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
[Inferior 1 (process 51969) exited normally]
gef➤ 
```

We have the flag

Flag: `flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}`
                               
And we're done xD

P.S Why i check the file type is to know if its x86 or x64 and if the biary is stripped or non stripped 


<br> <br>
[Back To Home](../../index.md)
<br>












                            
