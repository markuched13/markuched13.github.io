### Pandora HackTheBox

### Difficulty = Easy

### IP Address = 10.10.11.136

Nmap Tcp Scan:

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ nmap -sCV -A 10.10.11.136 -p22,80  
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-08 12:27 WAT
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.12 seconds
```

Only 2 tcp ports open. I'll check out the web server

Heading over to the web browser shows the domain name 
![image](https://user-images.githubusercontent.com/113513376/217517662-6b97d5db-8f58-455e-89ce-b141b174d768.png)

I added that to my `/etc/hosts` file already

While I fuzzed for directories i couldn't find any important directory also with vhosts

```
└─$ gobuster dir -u http://panda.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,zip,bak,db,html
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://panda.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/08 12:20:23 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 274]
/.htaccess            (Status: 403) [Size: 274]
/.htpasswd            (Status: 403) [Size: 274]
/assets               (Status: 301) [Size: 307] [--> http://panda.htb/assets/]
/index.html           (Status: 200) [Size: 33560]
/server-status        (Status: 403) [Size: 274]
Progress: 4613 / 4615 (99.96%)
===============================================================
2023/02/08 12:22:33 Finished
===============================================================
```

Scanning for udp ports show there's snmp open

```
└─$ sudo nmap -sCV -A 10.10.11.136 -p161  
[sudo] password for mark: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-08 12:29 WAT
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.28s latency).

PORT    STATE  SERVICE VERSION
161/tcp open snmp
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

TRACEROUTE (using port 161/tcp)
HOP RTT       ADDRESS
1   262.58 ms 10.10.16.1
2   137.36 ms panda.htb (10.10.11.136)

OS and Service detection performed. Please report any incorrect
```

Using hydra i got the community key

```
└─$ hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt snmp://panda.htb
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-08 12:31:56
[DATA] max 16 tasks per 1 server, overall 16 tasks, 118 login tries (l:1/p:118), ~8 tries per task
[DATA] attacking snmp://panda.htb:161/
[161][snmp] host: panda.htb   password: public
[STATUS] attack finished for panda.htb (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-08 12:31:57
```

Now i used snmpbulkwalk to enumerate the snmp service running cause its way faster than snmpwalk since it allows thread

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ snmpbulkwalk -Cr1000 -v 2c -c public panda.htb > snmpscan 
```

After spending a while looking at the data i got a process which runs a binary as user daniel 

```
└─$ cat snmpscan| grep /bin
iso.3.6.1.2.1.25.4.2.1.4.713 = STRING: "/usr/bin/VGAuthService"
iso.3.6.1.2.1.25.4.2.1.4.719 = STRING: "/usr/bin/vmtoolsd"
iso.3.6.1.2.1.25.4.2.1.4.758 = STRING: "/usr/bin/dbus-daemon"
iso.3.6.1.2.1.25.4.2.1.4.783 = STRING: "/usr/bin/python3"
iso.3.6.1.2.1.25.4.2.1.4.910 = STRING: "/bin/sh"
iso.3.6.1.2.1.25.4.2.1.4.1097 = STRING: "/usr/bin/host_check"
iso.3.6.1.2.1.25.4.2.1.5.783 = STRING: "/usr/bin/networkd-dispatcher --run-startup-triggers"
iso.3.6.1.2.1.25.4.2.1.5.910 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
```
                                                                 
Trying the username and password over ssh works `daniel:HotelBabylon23`

```
└─$ ssh daniel@panda.htb                                     
The authenticity of host 'panda.htb (10.10.11.136)' can't be established.
ED25519 key fingerprint is SHA256:yDtxiXxKzUipXy+nLREcsfpv/fRomqveZjm6PXq9+BY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'panda.htb' (ED25519) to the list of known hosts.
daniel@panda.htb's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed  8 Feb 11:38:16 UTC 2023

  System load:           0.0
  Usage of /:            63.1% of 4.87GB
  Memory usage:          8%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7d86

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$
```

There are two users so likely we are pivoting from user daniel to matt

```
daniel@pandora:~$ ls /home
daniel  matt
daniel@pandora:~$ 
```

Checking the webroot directory shows there's another instance running a web service

```
daniel@pandora:/var/www$ ls
html  pandora
daniel@pandora:/var/www$ cd pandora/
daniel@pandora:/var/www/pandora$ ls
index.html  pandora_console
daniel@pandora:/var/www/pandora$ cd pandora_console/
daniel@pandora:/var/www/pandora/pandora_console$ ls
ajax.php    composer.json  DEBIAN                extras   images        mobile                            pandora_console_logrotate_suse    pandoradb.sql                     vendor
attachment  composer.lock  docker_entrypoint.sh  fonts    include       operation                         pandora_console_logrotate_ubuntu  pandora_websocket_engine.service  ws.php
audit.log   COPYING        Dockerfile            general  index.php     pandora_console.log               pandora_console_upgrade           tests
AUTHORS     DB_Dockerfile  extensions            godmode  install.done  pandora_console_logrotate_centos  pandoradb_data.sql                tools
daniel@pandora:/var/www/pandora/pandora_console$ cd include/
daniel@pandora:/var/www/pandora/pandora_console/include$ cat config.php 
cat: config.php: Permission denied
daniel@pandora:/var/www/pandora/pandora_console/include$ ls -l config.
config.inc.php  config.php      
daniel@pandora:/var/www/pandora/pandora_console/include$ ls -l config.php 
-rw------- 1 matt matt 413 Dec  3  2021 config.php
```

We don't have access to view it too bad only user matt does

S
