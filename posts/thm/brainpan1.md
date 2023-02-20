### Brainpan TryHackMe

### IP Address = 10.10.217.241

Nmap Scan:

```
└─$ nmap -sV 10.10.217.241 -p9999,10000 -oN nmapscan 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-20 04:43 WAT
Nmap scan report for 10.10.217.241
Host is up (0.15s latency).

PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=2/20%Time=63F2EC74%P=x86_64-pc-linux-gnu%r(NU
SF:LL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\|
SF:\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\
SF:x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\x
SF:20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\|
SF:\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\x
SF:20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20_
SF:\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\x
SF:20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\x
SF:20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\x
SF:20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.44 seconds
```

From the scan we get a http server and a service running on port 9999

I'll check the http server to see what i can get

#### HTTP Enumeration

Checking the web server just shows a page talking about security vulnerabilities
![image](https://user-images.githubusercontent.com/113513376/220005052-a737da86-7c68-44c3-9766-00efe61316db.png)

I'll run gobuster to fuzz for directories and files

Gobuster found a /bin directory

```
└─$ gobuster dir -u http://10.10.217.241:10000/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.217.241:10000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/20 04:48:26 Starting gobuster in directory enumeration mode
===============================================================
/bin                  (Status: 301) [Size: 0] [--> /bin/]
/index.html           (Status: 200) [Size: 215]
Progress: 4611 / 4615 (99.91%)
===============================================================
2023/02/20 04:50:51 Finished
===============================================================

```

Checking it shows a binary
![image](https://user-images.githubusercontent.com/113513376/220005206-89b2de59-a84c-475f-a2d0-15b02ba35991.png)

I'll download it to my machine to analyze it

#### Binary File Analysis 

```
└─$ file brainpan.exe  
brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

We see that its a 32bits windows executable 

I'll check the protections enabled on the binary

```
└─$ rabin2 -I brainpan.exe  
arch     x86
baddr    0x31170000
binsz    21190
bintype  pe
bits     32
canary   false
retguard false
class    PE32
cmp.csum 0x0000dda1
compiled Mon Mar  4 16:21:12 2013
crypto   false
endian   little
havecode true
hdr.csum 0x0000dda1
laddr    0x0
lang     c
linenum  true
lsyms    false
machine  i386
nx       false
os       windows
overlay  true
cc       cdecl
pic      false
relocs   true
signed   false
sanitize false
static   false
stripped true
subsys   Windows CUI
va       true
```

From checking the protections enabled it doesn't have any protection enabled

And what's of interest to us is that no canary is found so if we get a buffer overflow we won't have to deal with bypassing canary, also NX is disasbled which is equivalent to DEP meaning that if we get a buffer overflow we can inject shellcode to the stack and execute it

I'll decompile the binary using ghidra

Here's the main function

```
int __cdecl _main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  size_t sVar2;
  size_t in_stack_fffff9f0;
  sockaddr local_5dc;
  undefined local_5cc [4];
  undefined4 local_5c8;
  SOCKET local_5b4;
  SOCKET local_5b0;
  WSADATA local_5ac;
  undefined4 local_414;
  undefined4 local_410;
  int local_40c;
  char *local_408;
  char *local_404;
  char *banner;
  char local_3fc [1016];
  
  __alloca(in_stack_fffff9f0);
  ___main();
  banner = 
  "_|                            _|                                        \n_|_|_|    _|  _|_|    _ |_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  \n_|    _|  _|_|      _|    _|  _|  _|    _|  _|     _|  _|    _|  _|    _|\n_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _ |\n_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|\n                                             _|                          \n                                            _ |\n\n[________________________ WELCOME TO BRAINPAN _________________________]\n                           ENTER THE PASSWORD                              \n\n                          >> "
  ;
  local_404 = "                          ACCESS DENIED\n";
  local_408 = "                          ACCESS GRANTED\n";
  local_410 = 9999;
  local_414 = 1;
  _printf("[+] initializing winsock...");
  iVar1 = _WSAStartup@8(0x202,&local_5ac);
  if (iVar1 == 0) {
    _printf("done.\n");
    iVar1 = 1;
    local_5b0 = _socket@12(2,1,0);
    if (local_5b0 == 0xffffffff) {
      iVar1 = _WSAGetLastError@0();
      _printf("[!] could not create socket: %d",iVar1);
    }
    _printf("[+] server socket created.\n",iVar1);
    local_5cc._0_2_ = 2;
    local_5c8 = 0;
    local_5cc._2_2_ = _htons@4(9999);
    iVar1 = _bind@12(local_5b0,(sockaddr *)local_5cc,0x10);
    if (iVar1 == -1) {
      iVar1 = _WSAGetLastError@0();
      _printf("[!] bind failed: %d",iVar1);
    }
    _printf("[+] bind done on port %d\n",local_410);
    _listen@8(local_5b0,3);
    _printf("[+] waiting for connections.\n");
    local_40c = 0x10;
    while (local_5b4 = _accept@12(local_5b0,&local_5dc,&local_40c), local_5b4 != 0xffffffff) {
      _printf("[+] received connection.\n");
      _memset(local_3fc,0,1000);
      sVar2 = _strlen(banner);
      _send@16(local_5b4,banner,sVar2,0);
      _recv@16(local_5b4,local_3fc,1000,0);
      local_414 = _get_reply(local_3fc);
      _printf("[+] check is %d\n",local_414);
      iVar1 = _get_reply(local_3fc);
      if (iVar1 == 0) {
        sVar2 = _strlen(local_404);
        _send@16(local_5b4,local_408,sVar2,0);
      }
      else {
        sVar2 = _strlen(local_408);
        _send@16(local_5b4,local_404,sVar2,0);
      }
      _closesocket@4(local_5b4);
    }
    iVar1 = _WSAGetLastError@0();
    _printf("[!] accept failed: %d",iVar1);
  }
  else {
    iVar1 = _WSAGetLastError@0();
    _printf("[!] winsock init failed: %d",iVar1);
  }
  return 1;
}
```


From the code we see that it creates:

```
1. It creates a socket on port 9999
2. Then prints out the banner
3. Calls function get_reply on our input as an argument
```

Here's get_reply decompiled code

```

void __cdecl _get_reply(char *input)

{
  size_t len;
  char reply [520];
  
  _printf("[get_reply] s = [%s]\n",input);
  _strcpy(reply,input);
  len = _strlen(reply);
  _printf("[get_reply] copied %d bytes to buffer\n",len);
  _strcmp(reply,"shitstorm\n");
  return;
}
```

We see that it copies our input value in the reply buffer, then it does a string compare of the value stored in reply buffer to shitstorm

There's a bug in the strcpy function call because it doesn't specify the amount of data to write in the reply buffer making us to overflow it and cause memory corruption

I'll run the binary 
![image](https://user-images.githubusercontent.com/113513376/220007694-eb247e85-d35d-4fe6-8c1f-36c77ac19995.png)

So it opens up a port and the service is running on port 9999

I can confirm by scanning it from my linux box

```
─$ nmap -sCV -p9999 windowpc.local -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-20 05:11 WAT
Nmap scan report for windowpc.local (192.168.144.26)
Host is up (0.0024s latency).

PORT     STATE SERVICE VERSION
9999/tcp open  abyss?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.77 seconds
```

I'll connect to the service using netcat

```
└─$ nc windowpc.local 9999 
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> shitstorm
                          ACCESS GRANTED                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/Brainpan]
└─$ 
```

We see it worked as expected and we got access granted since we gave the correct value

But this isn't what we want to do. We know that DEP is disabled meaning we can inject shellcode to the stack and execute it 

And since there's buffer overflow we can achieve this 

I'll run the binary again but this time around attach it to a debugger (as admin) in this case `Immunity Debugger`
![image](https://user-images.githubusercontent.com/113513376/220010047-07a6a4e0-8b0e-4701-9831-327d7c8b3643.png)

Now its going to be paused by default so i'll start the process `F9`
![image](https://user-images.githubusercontent.com/113513376/220010244-ca886b01-9298-4265-b8d8-b1b7cacfd138.png)

I'll set a working directory for mona to use `Mona is a python plugin used to automate and speed up specific searches while developing exploits (typically for the Windows platform)`
![image](https://user-images.githubusercontent.com/113513376/220011000-103ca470-5e6e-488b-9669-1d6475dc1cb5.png)

```
!mona config -set workingfolder c:\mona\%p
```

With this set i'll need to crash the server by giving it values that will overflow the reply buffer which is suppose to only hold up to 520 bytes of data

Using msf-patten_create i'll generate bytes of data

```
└─$ msf-pattern_create -l 600                       
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9     

```

On connecting to the remote server i'll give the value msf-pattern_create created to the remote service
![image](https://user-images.githubusercontent.com/113513376/220011739-70d7b0c8-c3e3-4e9c-8756-05f359d7b69b.png)

It hangs but back on the debugger we see it has crashed
![image](https://user-images.githubusercontent.com/113513376/220011797-a6bc664c-74bd-4270-94b1-1831fed43d24.png)

To get the offset i'll use mona to find the offset at where the eip `instruction pointer` tried accessing a wrong memory address
![image](https://user-images.githubusercontent.com/113513376/220012023-d1d95aae-68c9-4d22-83d6-e89315ac986c.png)

```
!mona findmsp distance 600
```

And from the result we see the EIP crashes at offset 524

```
[+] Looking for cyclic pattern in memory
    Cyclic pattern (normal) found at 0x0022f720 (length 600 bytes)
    Cyclic pattern (normal) found at 0x0022fb50 (length 600 bytes)
    -  Stack pivot between 544 & 1144 bytes needed to land in this pattern
    EIP contains normal pattern : 0x35724134 (offset 524)
    ESP (0x0022f930) points at offset 528 in normal pattern (length 72)
    EBP contains normal pattern : 0x72413372 (offset 520)
    EDX (0x0022f720) points at offset 0 in normal pattern (length 600)
[+] Examining SEH chain
[+] Examining stack (entire stack) - looking for cyclic pattern
    Walking stack from 0x0022d000 to 0x0022fffc (0x00002ffc bytes)
    0x0022f108 : Contains normal cyclic pattern at ESP-0x828 (-2088) : offset 23, length 577 (-> 0x0022f348 : ESP-0x5e7)
    0x0022f720 : Contains normal cyclic pattern at ESP-0x210 (-528) : offset 0, length 600 (-> 0x0022f977 : ESP+0x48)
    0x0022fb50 : Contains normal cyclic pattern at ESP+0x220 (+544) : offset 0, length 600 (-> 0x0022fda7 : ESP+0x478)
[+] Examining stack (entire stack) - looking for pointers to cyclic pattern
    Walking stack from 0x0022d000 to 0x0022fffc (0x00002ffc bytes)
    0x0022eb60 : Pointer into normal cyclic pattern at ESP-0xdd0 (-3536) : 0x0022f1b8 : offset 199, length 401
    0x0022ee98 : Pointer into normal cyclic pattern at ESP-0xa98 (-2712) : 0x0022f2c4 : offset 467, length 133
    0x0022f0dc : Pointer into normal cyclic pattern at ESP-0x854 (-2132) : 0x004d22b7 : offset 22, length 578
    0x0022f3cc : Pointer into normal cyclic pattern at ESP-0x564 (-1380) : 0x0022f314 : offset 547, length 53
    0x0022f5e4 : Pointer into normal cyclic pattern at ESP-0x34c (-844) : 0x0022f874 : offset 340, length 260
    0x0022f608 : Pointer into normal cyclic pattern at ESP-0x328 (-808) : 0x0022f8c8 : offset 424, length 176
    0x0022f710 : Pointer into normal cyclic pattern at ESP-0x220 (-544) : 0x0022f720 : offset 0, length 600
    0x0022fa80 : Pointer into normal cyclic pattern at ESP+0x150 (+336) : 0x0022fb6c : offset 28, length 572
    0x0022fa8c : Pointer into normal cyclic pattern at ESP+0x15c (+348) : 0x0022fb68 : offset 24, length 576
    0x0022fb2c : Pointer into normal cyclic pattern at ESP+0x1fc (+508) : 0x0022fc24 : offset 212, length 388
```






