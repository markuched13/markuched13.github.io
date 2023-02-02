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
