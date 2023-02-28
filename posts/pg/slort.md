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

`


