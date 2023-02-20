### BrainStorm TryHackMe

### Difficulty = Medium

### IP Address =  10.10.249.147 

Nmap Scan

```
└─$ nmap -sCV 10.10.249.147 -p21,3389,9999 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-20 04:20 WAT
Stats: 0:02:52 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.76% done; ETC: 04:23 (0:00:00 remaining)
Nmap scan report for 10.10.249.147
Host is up (0.15s latency).

PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: BRAINSTORM
|   NetBIOS_Domain_Name: BRAINSTORM
|   NetBIOS_Computer_Name: BRAINSTORM
|   DNS_Domain_Name: brainstorm
|   DNS_Computer_Name: brainstorm
|   Product_Version: 6.1.7601
|_  System_Time: 2023-02-20T03:23:14+00:00
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2023-02-19T03:16:46
|_Not valid after:  2023-08-21T03:16:46
|_ssl-date: 2023-02-20T03:23:45+00:00; 0s from scanner time.
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=2/20%Time=63F2E706%P=x86_64-pc-linux-gnu%r(NU
SF:LL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter
SF:\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequest
SF:,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x
SF:20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20mes
SF:sage:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(
SF:beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20character
SF:s\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome\x2
SF:0to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20usern
SF:ame\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(J
SF:avaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20e
SF:nter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\
SF:x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20cha
SF:t\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20ch
SF:aracters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcome\x
SF:20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20user
SF:name\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(
SF:RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x2
SF:0enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20
SF:a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brainst
SF:orm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x
SF:2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReques
SF:tTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ent
SF:er\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x2
SF:0message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(bet
SF:a\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\)
SF::\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\x20
SF:Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20
SF:\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Terminal
SF:ServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPleas
SF:e\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write
SF:\x20a\x20message:\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.34 seconds

```

From the scan just only 3 tcp ports are open and its a windows box

#### FTP Enumeration

```
─$ ftp 10.10.249.147
Connected to 10.10.249.147.
220 Microsoft FTP Service
Name (10.10.249.147:mark): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls -al
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-29-19  07:36PM       <DIR>          chatserver
226 Transfer complete.
ftp> cd chatserver
250 CWD command successful.
ftp> ls -al
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-29-19  09:26PM                43747 chatserver.exe
08-29-19  09:27PM                30761 essfunc.dll
226 Transfer complete.
ftp> prompt off
Interactive mode off.
ftp> mget *
local: chatserver.exe remote: chatserver.exe
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |***********************************************************| 43747       50.13 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 45 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
43747 bytes received in 00:00 (50.07 KiB/s)
local: essfunc.dll remote: essfunc.dll
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |***********************************************************| 30761       46.35 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 32 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
30761 bytes received in 00:00 (46.33 KiB/s)
ftp> exit
221 Goodbye.
```

We got an exe file with a dll file 

```
└─$ file chatserver.exe                                   
chatserver.exe: MS-DOS executable
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/Brainstorm]
└─$ file essfunc.dll   
essfunc.dll: MS-DOS executable
```

I'll do a basic file check on the executable

```
└─$ rabin2 -I chatserver.exe 
ii 1168 64
arch     x86
baddr    0xffffffffffffffff
binsz    43718
bintype  mz
bits     16
canary   false
class    MZ
crypto   false
endian   little
havecode true
laddr    0x0
linenum  false
lsyms    false
machine  i386
nx       false
os       DOS
pic      false
relocs   false
sanitize false
static   true
stripped false
subsys   DOS
va       true
```

We see that its a x86 binary and no canary found, no nx which is equivalent to DEP i.e prevents shellcode injection to the stack and execution

#### Binary File Analysis

At first i would want to open the binary up in ghidra but that isn't going to decompile to a high level language

Reason below: 

```
Firstly, MS-DOS executables were typically written in assembly language, which is a low-level language that is difficult to decompile back into high-level source code. While Ghidra can disassemble such executables and show the assembly instructions, it may not be able to generate high-level code that is easy to read and understand.
```

So i'll run the binary to know what it does




               
