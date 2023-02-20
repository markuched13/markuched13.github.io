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

So we opens up a port and the service is running on port 9999

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

