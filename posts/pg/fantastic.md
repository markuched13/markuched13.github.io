First thing first we start with scanning the host for open ports using rustscan then use nmap to further enumerate those open ports

```
# Nmap 7.92 scan initiated Fri Jan 13 15:21:46 2023 as: nmap -sCV -A -p22,3000,9090 -oN nmaptcp 192.168.68.181
Nmap scan report for 192.168.68.181
Host is up (0.27s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 13 Jan 2023 14:22:45 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 13 Jan 2023 14:21:57 GMT
|     Content-Length: 29
|_    href="/login">Found</a>.
9090/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-title: Prometheus Time Series Collection and Processing Server
|_Requested resource was /graph
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 13 15:24:17 2023 -- 1 IP address (1 host up) scanned in 150.86 seconds
```

From the scan we see only 3 ports are open which are port 22, 3000, 9090

Now lets check out the content of port 3000 which is running a web server

On naviating there we are greeted with a login page
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/2.png)

From the page we see its running grafana and looking below we see the version number which is v8.3.0

Now next thing to do is search for public known exploit on grafana v8.3.0

And with searching I got this which is a directory transversal vulnerability
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/3.png)

With this we can use it to read the grafana database and its config file (/etc/grafana/granfan.ini)

So lets read the config file and from the result we see the location where the db will be stored in 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/4.png)

The content is quite much so instead let me do it manually and save it in a file
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/6.png)

Now i have the db file i'll be using sqlitebrowser to naviagate through it
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/7.png)

Also when navigating to the data_source table we get an encrypted credential 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/11.png)

In order to decrypt it we need the secret key which will be gotten from the grafana.ini file 

So lets download it to our local machine
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/9.png)

Now viewing it we get the secret key for the db file
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/10.png)

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/14.png)

Now we have everything we need to decrypt the encrypted db file which contains the password of a user

Using this resource which is a go script that will decode the AES encrypted password in the db file: https://github.com/jas502n/Grafana-CVE-2021-43798

Now we need to edit the AESDecrypt.go file to decode the encrypted password
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/13.png)

Now lets replace the `var dataSourcePassword value with the encypted password`
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/12.png)

Now lets run the go script 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/15.png)

And boom it decoded to `SuperSecureP@ssw0rd`

And the user who has that password is `sysadmin`

Now lets login via ssh using the newly found credential `sysadmin:SuperSecureP@ssw0rd`
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/16.png)

Also we see the user belongs to the disk group 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/17.png)

Also we have access to all the mounted disk in the system including the /root partition 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/18.png)

Using this resource I was able to read the root id_rsa file: https://vk9-sec.com/disk-group-privilege-escalation/
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/19.png)

Now next thing i was to save the idrsa file on my machine change the permission read/write and login as root using the sshkey
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Fantastic/20.png)

And we're done xD

<br> <br>
[Back To Home](../../index.md)
<br>




















