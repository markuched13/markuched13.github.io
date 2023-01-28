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




                            
