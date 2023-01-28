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


                            
