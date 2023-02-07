### Nest HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.178

Nmap Scan:

```
# Nmap 7.92 scan initiated Tue Feb  7 01:45:24 2023 as: nmap -sCV -A -p445,4386 -oN nmapscan -Pn 10.10.10.178
Nmap scan report for 10.10.10.178
Host is up (0.18s latency).

PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.92%I=7%D=2/7%Time=63E19F2C%P=x86_64-pc-linux-gnu%r(NUL
SF:L,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLine
SF:s,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised
SF:\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20
SF:V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comman
SF:d\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n
SF:\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repor
SF:ting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"\
SF:r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nHQK\x
SF:20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allows\x
SF:20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x20the
SF:\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20---\
SF:r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>\r\n
SF:DEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCookie
SF:,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessionRe
SF:q,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerberos,21
SF:,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest,3A,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20c
SF:ommand\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x20Re
SF:porting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK\x20
SF:Reporting\x20Service\x20V1\.2\r\n\r\n>");

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-07T00:48:14
|_  start_date: 2023-02-07T00:06:46
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb  7 01:48:54 2023 -- 1 IP address (1 host up) scanned in 209.13 seconds

```

Checking smb

```
┌──(venv)─(mark__haxor)-[/tmp/pwn]
└─$ smbclient -L 10.10.10.178
Password for [WORKGROUP\mark]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        Secure$         Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.178 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```

I'll check if i can connect to the shares in the smb

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ smbclient //10.10.10.178/Data                          
Password for [WORKGROUP\mark]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 23:53:46 2019
  ..                                  D        0  Wed Aug  7 23:53:46 2019
  IT                                  D        0  Wed Aug  7 23:58:07 2019
  Production                          D        0  Mon Aug  5 22:53:38 2019
  Reports                             D        0  Mon Aug  5 22:53:44 2019
  Shared                              D        0  Wed Aug  7 20:07:51 2019

                5242623 blocks of size 4096. 1840001 blocks available
smb: \> q
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ smbclient //10.10.10.178/Users
Password for [WORKGROUP\mark]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 00:04:21 2020
  ..                                  D        0  Sun Jan 26 00:04:21 2020
  Administrator                       D        0  Fri Aug  9 16:08:23 2019
  C.Smith                             D        0  Sun Jan 26 08:21:44 2020
  L.Frost                             D        0  Thu Aug  8 18:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 18:02:50 2019
  TempUser                            D        0  Wed Aug  7 23:55:56 2019

                5242623 blocks of size 4096. 1840001 blocks available
smb: \> q
```

I'll try mounting it and accessing what is in those shares

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ mkdir mount     

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=anonymous' //10.10.10.178/Data mount 
[sudo] password for mark: 
Password for anonymous@//10.10.10.178/Data: 

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ mkdir mount2 

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=anonymous' //10.10.10.178/Users mount2
Password for anonymous@//10.10.10.178/Users: 
```

Now time to see if i can loot anything from here

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]
└─$ ls -R .
.:
IT  Production  Reports  Shared

./IT:
ls: reading directory './IT': Permission denied

./Production:
ls: reading directory './Production': Permission denied

./Reports:
ls: reading directory './Reports': Permission denied

./Shared:
Maintenance  Templates

./Shared/Maintenance:
'Maintenance Alerts.txt'

./Shared/Templates:
HR  Marketing

./Shared/Templates/HR:
'Welcome Email.txt'

./Shared/Templates/Marketing:
```

We can't view most directories so i'll check out the ones we have access to

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]
└─$ cd Shared/Templates/HR 
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/mount/Shared/Templates/HR]
└─$ ls     
'Welcome Email.txt'
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/mount/Shared/Templates/HR]
└─$ cat Welcome\ Email.txt 
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR
```

This is a welcome email saying all users should keep their username as Firstname Surname 

Also there's a cred which we can use to access the user share

THe other file doesn't contain much

```
┌──(venv)─(mark__haxor)-[~/_/Nest/mount/Shared/Maintenance]
└─$ cat Maintenance\ Alerts.txt 
There is currently no scheduled maintenance work
```

Now i'll unmount the first share

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo umount mount                                                 
[sudo] password for mark: 

```

On attempting to list files in the second mounted directory we get permission denied as expected cause this requires valid cred to list shares

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ cd mount2  
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ ls
Administrator  C.Smith  L.Frost  R.Thompson  TempUser
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ ls -R  
.:
Administrator  C.Smith  L.Frost  R.Thompson  TempUser

./Administrator:
ls: reading directory './Administrator': Permission denied

./C.Smith:
ls: reading directory './C.Smith': Permission denied

./L.Frost:
ls: reading directory './L.Frost': Permission denied

./R.Thompson:
ls: reading directory './R.Thompson': Permission denied

./TempUser:
ls: reading directory './TempUser': Permission denied
```

So i'll use the TempUser cred to mount the user share

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo umount mount2

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=TempUser' //10.10.10.178/Users mount2
Password for TempUser@//10.10.10.178/Users: 
```

Checking if we can list directory

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ cd mount2 

┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ ls -R .
.:
Administrator  C.Smith  L.Frost  R.Thompson  TempUser

./Administrator:
ls: reading directory './Administrator': Permission denied

./C.Smith:
ls: reading directory './C.Smith': Permission denied

./L.Frost:
ls: reading directory './L.Frost': Permission denied

./R.Thompson:
ls: reading directory './R.Thompson': Permission denied

./TempUser:
'New Text Document.txt'

┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ cd TempUser 

┌──(venv)─(mark__haxor)-[~/_/HTB/Nest/mount2/TempUser]
└─$ cat New\ Text\ Document.txt 
```

Still not full access yet. If you notice the password for the TempUser which is `welcome2019` it is possible for any of the user to have not changed his/her cred from the default one

I'll attempt to spray the password over smb

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ ls     
Administrator  C.Smith  L.Frost  R.Thompson  TempUser
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ ls > ../users
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ cd ..
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ cat users                  
Administrator
C.Smith
L.Frost
R.Thompson
TempUser
```

Now using `crackmapexec` i'll attempt to perform password spraying using the cred `welcome2019` on the user list

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ crackmapexec smb 10.10.10.178 -u users -p welcome2019            
SMB         10.10.10.178    445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.10.10.178    445    HTB-NEST         [-] HTB-NEST\Administrator:welcome2019 STATUS_LOGON_FAILURE 
SMB         10.10.10.178    445    HTB-NEST         [-] HTB-NEST\C.Smith:welcome2019 STATUS_LOGON_FAILURE 
SMB         10.10.10.178    445    HTB-NEST         [+] HTB-NEST\L.Frost:welcome2019 
```

It worked we have another valid cred `L.Frost:welcome2019`

Let see what this user have access to

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ smbmap -H 10.10.10.178 -u L.Frost -p welcome2019
[+] Guest session       IP: 10.10.10.178:445    Name: 10.10.10.178                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 NO ACCESS
        Users                                                   READ ONLY
```

Just the data & user share 

I'll mount it as i did before using the user's cred

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=L.Frost' //10.10.10.178/Users mount2
Password for L.Frost@//10.10.10.178/Users: 

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=L.Frost' //10.10.10.178/Data mount 
Password for L.Frost@//10.10.10.178/Data: 
```

Loot for stuffs again

Nothin really interesting in the Data share

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ cd mount 
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]
└─$ ls -R .      
.:
IT  Production  Reports  Shared

./IT:
ls: reading directory './IT': Permission denied

./Production:
ls: reading directory './Production': Permission denied

./Reports:
ls: reading directory './Reports': Permission denied

./Shared:
Maintenance  Templates

./Shared/Maintenance:
'Maintenance Alerts.txt'

./Shared/Templates:
HR  Marketing

./Shared/Templates/HR:
'Welcome Email.txt'

./Shared/Templates/Marketing:
```

This is weird not much access here

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ cd mount2   
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ ls -R .
.:
Administrator  C.Smith  L.Frost  R.Thompson  TempUser

./Administrator:
ls: reading directory './Administrator': Permission denied

./C.Smith:
ls: reading directory './C.Smith': Permission denied

./L.Frost:
ls: reading directory './L.Frost': Permission denied

./R.Thompson:
ls: reading directory './R.Thompson': Permission denied

./TempUser:
ls: reading directory './TempUser': Permission denied
```

Now on remembering the spraying i did it didn't really spray on all users it stopped when it got a successfull login 

So i'll rerun the password spray but this time add a switch to keep it running even tho it gets a valid login

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ crackmapexec smb 10.10.10.178 -u users -p welcome2019 --continue-on-success
SMB         10.10.10.178    445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.10.10.178    445    HTB-NEST         [-] HTB-NEST\Administrator:welcome2019 STATUS_LOGON_FAILURE 
SMB         10.10.10.178    445    HTB-NEST         [-] HTB-NEST\C.Smith:welcome2019 STATUS_LOGON_FAILURE 
SMB         10.10.10.178    445    HTB-NEST         [+] HTB-NEST\L.Frost:welcome2019 
SMB         10.10.10.178    445    HTB-NEST         [+] HTB-NEST\R.Thompson:welcome2019 
SMB         10.10.10.178    445    HTB-NEST         [+] HTB-NEST\TempUser:welcome2019 
```

Cool we have another user i'll check what share he has access to and mount it

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ smbmap -H 10.10.10.178 -u R.Thompson -p welcome2019                        
[+] Guest session       IP: 10.10.10.178:445    Name: 10.10.10.178                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 NO ACCESS
        Users                                                   READ ONLY

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=R.Thompson' //10.10.10.178/Data mount
Password for R.Thompson@//10.10.10.178/Data: 

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=R.Thompson' //10.10.10.178/Users mount2
Password for R.Thompson@//10.10.10.178/Users: 
```

Looting stuffs again

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]                                                                                                                                                                   
└─$ cd mount                                                                                                                                                                                                       
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]                                                                                                                                                                   
└─$ ls -R .                                                                                                                                                                                                        
.:                                                                                                                                                                                                                 
IT  Production  Reports  Shared

./IT:                                                                                                                                                                                                              
ls: reading directory './IT': Permission denied

./Production:
ls: reading directory './Production': Permission denied

./Reports:
ls: reading directory './Reports': Permission denied 

./Shared:
Maintenance  Templates

./Shared/Maintenance:
'Maintenance Alerts.txt'

./Shared/Templates:
HR  Marketing

./Shared/Templates/HR:
'Welcome Email.txt'

./Shared/Templates/Marketing:

┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]
└─$ cd ..

┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ cd mount2 

┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount2]
└─$ ls -R .
.:
Administrator  C.Smith  L.Frost  R.Thompson  TempUser

./Administrator:
ls: reading directory './Administrator': Permission denied

./C.Smith:
ls: reading directory './C.Smith': Permission denied

./L.Frost:
ls: reading directory './L.Frost': Permission denied

./R.Thompson:
ls: reading directory './R.Thompson': Permission denied

./TempUser:
ls: reading directory './TempUser': Permission denied
```

Damnn i got nothing 

I figured out the problem. Using any cred whether correct or not to connect to share will work

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ smbclient //10.10.10.178/Users -U R.Thompson                       
Password for [WORKGROUP\R.Thompson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 00:04:21 2020
  ..                                  D        0  Sun Jan 26 00:04:21 2020
  Administrator                       D        0  Fri Aug  9 16:08:23 2019
  C.Smith                             D        0  Sun Jan 26 08:21:44 2020
  L.Frost                             D        0  Thu Aug  8 18:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 18:02:50 2019
  TempUser                            D        0  Wed Aug  7 23:55:56 2019

                5242623 blocks of size 4096. 1839999 blocks available
smb: \> q
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ smbclient //10.10.10.178/Users -U R.Thompson
Password for [WORKGROUP\R.Thompson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 00:04:21 2020
  ..                                  D        0  Sun Jan 26 00:04:21 2020
  Administrator                       D        0  Fri Aug  9 16:08:23 2019
  C.Smith                             D        0  Sun Jan 26 08:21:44 2020
  L.Frost                             D        0  Thu Aug  8 18:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 18:02:50 2019
  TempUser                            D        0  Wed Aug  7 23:55:56 2019

                5242623 blocks of size 4096. 1839999 blocks available
smb: \> q
```

So i have no idea why crackmapexec gave that result 🤔

Anyways i'll try mounting share again as TempUser cause i figured out that there's a directory which i missed 😞

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ sudo mount -t cifs -o 'user=TempUser' //10.10.10.178/Data mount  
Password for TempUser@//10.10.10.178/Data: 
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ cd mount 
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]
└─$ tree
.
├── IT
│__ ├── Archive
│__ ├── Configs
│__ │__ ├── Adobe
│__ │__ │__ ├── editing.xml
│__ │__ │__ ├── Options.txt
│__ │__ │__ ├── projects.xml
│__ │__ │__ └── settings.xml
│__ │__ ├── Atlas
│__ │__ │__ └── Temp.XML
│__ │__ ├── DLink
│__ │__ ├── Microsoft
│__ │__ │__ └── Options.xml
│__ │__ ├── NotepadPlusPlus
│__ │__ │__ ├── config.xml
│__ │__ │__ └── shortcuts.xml
│__ │__ ├── RU Scanner
│__ │__ │__ └── RU_config.xml
│__ │__ └── Server Manager
│__ ├── Installs
│__ ├── Reports
│__ └── Tools
├── Production
├── Reports
└── Shared
    ├── Maintenance
    │__ └── Maintenance Alerts.txt
    └── Templates
        ├── HR
        │__ └── Welcome Email.txt
        └── Marketing

20 directories, 11 files
```

Ah cool we get more output so the problem was cause i used `ls -R .`

Anyways we some that most files in there are .xml file and there's a NotePadPlusPlus config file among it

I'll cat the file to know its content, but for some reason it doesn't show 

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]
└─$ cp IT/Archive/Configs/NotepadPlusPlus/config.xml ../
cp: cannot stat 'IT/Archive/Configs/NotepadPlusPlus/config.xml': No such file or directory

┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Nest/mount]
└─$ cd IT/Archive 

┌──(venv)─(mark__haxor)-[~/_/Nest/mount/IT/Archive]
└─$ ls     

┌──(venv)─(mark__haxor)-[~/_/Nest/mount/IT/Archive]
└─$ ls -al 
total 4
drwxr-xr-x 2 root root    0 Aug  5  2019 .
drwxr-xr-x 2 root root 4096 Aug  7  2019 ..
```

I'll get it by just connecting to the share 

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Nest]
└─$ smbclient -U TempUser //10.10.10.178/data welcome2019
Password for [WORKGROUP\TempUser]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 23:53:46 2019
  ..                                  D        0  Wed Aug  7 23:53:46 2019
  IT                                  D        0  Wed Aug  7 23:58:07 2019
  Production                          D        0  Mon Aug  5 22:53:38 2019
  Reports                             D        0  Mon Aug  5 22:53:44 2019
  Shared                              D        0  Wed Aug  7 20:07:51 2019

                5242623 blocks of size 4096. 1839999 blocks available
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Shared/Maintenance/Maintenance Alerts.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Configs\Adobe\editing.xml of size 246 as IT/Configs/Adobe/editing.xml (0.5 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \IT\Configs\Adobe\Options.txt of size 0 as IT/Configs/Adobe/Options.txt (0.0 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \IT\Configs\Adobe\projects.xml of size 258 as IT/Configs/Adobe/projects.xml (0.5 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \IT\Configs\Adobe\settings.xml of size 1274 as IT/Configs/Adobe/settings.xml (1.9 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \IT\Configs\Atlas\Temp.XML of size 1369 as IT/Configs/Atlas/Temp.XML (2.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \IT\Configs\Microsoft\Options.xml of size 4598 as IT/Configs/Microsoft/Options.xml (6.7 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\config.xml of size 6451 as IT/Configs/NotepadPlusPlus/config.xml (9.3 KiloBytes/sec) (average 3.1 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\shortcuts.xml of size 2108 as IT/Configs/NotepadPlusPlus/shortcuts.xml (2.8 KiloBytes/sec) (average 3.0 KiloBytes/sec)
getting file \IT\Configs\RU Scanner\RU_config.xml of size 270 as IT/Configs/RU Scanner/RU_config.xml (0.5 KiloBytes/sec) (average 2.8 KiloBytes/sec)
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Shared/Templates/HR/Welcome Email.txt (0.8 KiloBytes/sec) (average 2.6 KiloBytes/sec)
smb: \> q
```

Now i'll cat the file

```
<?xml version="1.0" encoding="Windows-1252" ?>
<NotepadPlus>
    <GUIConfigs>
        <!-- 3 status : "large", "small" or "hide"-->
        <GUIConfig name="ToolBar" visible="yes">standard</GUIConfig>
        <!-- 2 status : "show" or "hide"-->
        <GUIConfig name="StatusBar">show</GUIConfig>
        <!-- For all attributs, 2 status : "yes" or "no"-->
        <GUIConfig name="TabBar" dragAndDrop="yes" drawTopBar="yes" drawInactiveTab="yes" reduce="yes" closeButton="no" doubleClick2Close="no" vertical="no" multiLine="no" hide="no" />
        <!-- 2 positions : "horizontal" or "vertical"-->
        <GUIConfig name="ScintillaViewsSplitter">vertical</GUIConfig>
        <!-- For the attribut of position, 2 status : docked or undocked ; 2 status : "show" or "hide" -->
        <GUIConfig name="UserDefineDlg" position="undocked">hide</GUIConfig>
        <GUIConfig name="TabSetting" size="4" replaceBySpace="no" />
        <!--App position-->
        <GUIConfig name="AppPosition" x="662" y="95" width="955" height="659" isMaximized="yes" />
        <!-- For the primary scintilla view,
             2 status for Attribut lineNumberMargin, bookMarkMargin, indentGuideLine and currentLineHilitingShow: "show" or "hide"
             4 status for Attribut folderMarkStyle : "simple", "arrow", "circle" and "box"  -->
        <GUIConfig name="ScintillaPrimaryView" lineNumberMargin="show" bookMarkMargin="show" folderMarkStyle="box" indentGuideLine="show" currentLineHilitingShow="show" Wrap="yes" edge="no" edgeNbColumn="100" wrapSymbolShow="hide" zoom="0" whiteSpaceShow="hide" eolShow="hide" lineWrapMethod="aligned" zoom2="0" />
        <!-- For the secodary scintilla view,
             2 status for Attribut lineNumberMargin, bookMarkMargin, indentGuideLine and currentLineHilitingShow: "show" or "hide"
             4 status for Attribut folderMarkStyle : "simple", "arrow", "circle" and "box" -->
        <GUIConfig name="Auto-detection">yes</GUIConfig>
        <GUIConfig name="CheckHistoryFiles">no</GUIConfig>
        <GUIConfig name="TrayIcon">no</GUIConfig>
        <GUIConfig name="RememberLastSession">yes</GUIConfig>
        <!--
			New Document default settings :
				format = 0/1/2 -> win/unix/mac
				encoding = 0/1/2/3/4/5 -> ANSI/UCS2Big/UCS2small/UTF8/UTF8-BOM
				defaultLang = 0/1/2/..

			Note 1 : UTF8-BOM -> UTF8 without BOM
			Note 2 : for defaultLang :
					0 -> L_TXT
					1 -> L_PHP
					... (see source file)
		-->
        <GUIConfig name="NewDocDefaultSettings" format="0" encoding="0" lang="0" codepage="-1" openAnsiAsUTF8="no" />
        <GUIConfig name="langsExcluded" gr0="0" gr1="0" gr2="0" gr3="0" gr4="0" gr5="0" gr6="0" gr7="0" langMenuCompact="yes" />
        <!--
		printOption is print colour setting, the following values are possible :
			0 : WYSIWYG
			1 : Invert colour
			2 : B & W
			3 : WYSIWYG but without background colour
		-->
        <GUIConfig name="Print" lineNumber="no" printOption="0" headerLeft="$(FULL_CURRENT_PATH)" headerMiddle="" headerRight="$(LONG_DATE) $(TIME)" headerFontName="IBMPC" headerFontStyle="1" headerFontSize="8" footerLeft="" footerMiddle="-$(CURRENT_PRINTING_PAGE)-" footerRight="" footerFontName="" footerFontStyle="0" footerFontSize="9" margeLeft="0" margeTop="0" margeRight="0" margeBottom="0" />
        <!--
                            Backup Setting :
                                0 : non backup
                                1 : simple backup
                                2 : verbose backup
                      -->
        <GUIConfig name="Backup" action="0" useCustumDir="no" dir="" />
        <GUIConfig name="TaskList">yes</GUIConfig>
        <GUIConfig name="SaveOpenFileInSameDir">no</GUIConfig>
        <GUIConfig name="noUpdate" intervalDays="15" nextUpdateDate="20080426">no</GUIConfig>
        <GUIConfig name="MaitainIndent">yes</GUIConfig>
        <GUIConfig name="MRU">yes</GUIConfig>
        <GUIConfig name="URL">0</GUIConfig>
        <GUIConfig name="globalOverride" fg="no" bg="no" font="no" fontSize="no" bold="no" italic="no" underline="no" />
        <GUIConfig name="auto-completion" autoCAction="0" triggerFromNbChar="1" funcParams="no" />
        <GUIConfig name="sessionExt"></GUIConfig>
        <GUIConfig name="SmartHighLight">yes</GUIConfig>
        <GUIConfig name="TagsMatchHighLight" TagAttrHighLight="yes" HighLightNonHtmlZone="no">yes</GUIConfig>
        <GUIConfig name="MenuBar">show</GUIConfig>
        <GUIConfig name="Caret" width="1" blinkRate="250" />
        <GUIConfig name="ScintillaGlobalSettings" enableMultiSelection="no" />
        <GUIConfig name="openSaveDir" value="0" defaultDirPath="" />
        <GUIConfig name="titleBar" short="no" />
        <GUIConfig name="DockingManager" leftWidth="200" rightWidth="200" topHeight="200" bottomHeight="266">
            <FloatingWindow cont="4" x="39" y="109" width="531" height="364" />
            <PluginDlg pluginName="dummy" id="0" curr="3" prev="-1" isVisible="yes" />
            <PluginDlg pluginName="NppConverter.dll" id="3" curr="4" prev="0" isVisible="no" />
            <ActiveTabs cont="0" activeTab="-1" />
            <ActiveTabs cont="1" activeTab="-1" />
            <ActiveTabs cont="2" activeTab="-1" />
            <ActiveTabs cont="3" activeTab="-1" />
        </GUIConfig>
    </GUIConfigs>
    <!-- The History of opened files list -->
    <FindHistory nbMaxFindHistoryPath="10" nbMaxFindHistoryFilter="10" nbMaxFindHistoryFind="10" nbMaxFindHistoryReplace="10" matchWord="no" matchCase="no" wrap="yes" directionDown="yes" fifRecuisive="yes" fifInHiddenFolder="no" dlgAlwaysVisible="no" fifFilterFollowsDoc="no" fifFolderFollowsDoc="no" searchMode="0" transparencyMode="0" transparency="150">
        <Find name="text" />
        <Find name="txt" />
        <Find name="itx" />
        <Find name="iTe" />
        <Find name="IEND" />
        <Find name="redeem" />
        <Find name="activa" />
        <Find name="activate" />
        <Find name="redeem on" />
        <Find name="192" />
        <Replace name="C_addEvent" />
    </FindHistory>
    <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
    </History>
</NotepadPlus>
```

There's lot of stuff in it and noticing the find history tag we see there are path disclosed 

Lookin at the files there's another config file

```
IT/Configs/RU Scanner/RU_config.xml
```

I'll cat the file

```
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile> 
```

Cool we have the cred for another user called c.smith and her password which is 
