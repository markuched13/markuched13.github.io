### BIC 2023 WINTER CTF 

### Description: This is a CTF hosted by Blacks In Cybersecurity

##### It was a fun challenge which I focused only on solving all pwn challenges but sadly they only brought one pwn challenge. I was able to solve the pwn challenge with an easy reverse engineering chall. Lets get straight to it

#### Reverse Engineering 

Firstly i'll do the easy reverse engineering challenge 

Basic file checks

```
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ file chall       
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=32b061e72f3608b65f0649e1f97e7d5d5b049b87, for GNU/Linux 3.2.0, stripped
```

From the file check we know that its a x64 binary and its statically linked (meaning that all libraries that the executable needs are integrated inside) and also is stripped ( meaning that we won't be able to see the function names)

Lets run it to know what it does

```
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ ./chall       
/===========================================================================\
|               Welcome to BIC Winter CTF \0/                               |
+===========================================================================+
[ERROR] Login information missing
Usage: ./chall <username> <password>
```

It requires passing two parameters which are username and password

Since i don't know it lets decompile the binary using ghidra

After decompiling 
